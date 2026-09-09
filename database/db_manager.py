"""
Database Manager for Account Hijacking Detection System.
Supports MongoDB (via PyMongo) with transparent local document-store fallback for zero-dependency local execution.
"""
import os
import json
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "db.json")
MONGODB_URI = os.getenv("MONGODB_URI", "")

class LocalCollection:
    """Thread-safe document collection with MongoDB-compatible query and mutation interface."""
    def __init__(self, name: str, parent_db: 'LocalDatabase'):
        self.name = name
        self.parent = parent_db

    def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        docs = self.parent.get_collection_data(self.name)
        for doc in docs:
            if self._matches(doc, query):
                return json.loads(json.dumps(doc))
        return None

    def find(self, query: Optional[Dict[str, Any]] = None, sort_key: Optional[str] = None, reverse: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
        docs = self.parent.get_collection_data(self.name)
        results = []
        for doc in docs:
            if query is None or self._matches(doc, query):
                results.append(json.loads(json.dumps(doc)))
        if sort_key:
            results.sort(key=lambda x: x.get(sort_key, ""), reverse=reverse)
        return results[:limit]

    def insert_one(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            doc_copy = json.loads(json.dumps(doc))
            if "_id" not in doc_copy:
                doc_copy["_id"] = f"{self.name}_{int(datetime.now(timezone.utc).timestamp() * 1000)}_{len(docs) + 1}"
            docs.append(doc_copy)
            self.parent.save()
            return {"inserted_id": doc_copy["_id"]}

    def update_one(self, query: Dict[str, Any], update: Dict[str, Any]) -> bool:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            for i, doc in enumerate(docs):
                if self._matches(doc, query):
                    if "$set" in update:
                        for k, v in update["$set"].items():
                            doc[k] = v
                    if "$push" in update:
                        for k, v in update["$push"].items():
                            if k not in doc or not isinstance(doc[k], list):
                                doc[k] = []
                            doc[k].append(v)
                    docs[i] = doc
                    self.parent.save()
                    return True
            return False

    def delete_one(self, query: Dict[str, Any]) -> bool:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            for i, doc in enumerate(docs):
                if self._matches(doc, query):
                    docs.pop(i)
                    self.parent.save()
                    return True
            return False

    def delete_many(self, query: Dict[str, Any]) -> int:
        with self.parent.lock:
            docs = self.parent.get_collection_data(self.name)
            initial_count = len(docs)
            remaining = [doc for doc in docs if not self._matches(doc, query)]
            self.parent.set_collection_data(self.name, remaining)
            deleted_count = initial_count - len(remaining)
            if deleted_count > 0:
                self.parent.save()
            return deleted_count

    def count_documents(self, query: Optional[Dict[str, Any]] = None) -> int:
        docs = self.parent.get_collection_data(self.name)
        if not query:
            return len(docs)
        return sum(1 for doc in docs if self._matches(doc, query))

    def _matches(self, doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
        for key, val in query.items():
            if key == "$or":
                return any(self._matches(doc, subq) for subq in val)
            if doc.get(key) != val:
                return False
        return True


class LocalDatabase:
    """Thread-safe persistent JSON document store mirroring MongoDB."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.lock = threading.RLock()
        self.data: Dict[str, List[Dict[str, Any]]] = {
            "users": [],
            "active_sessions": [],
            "security_events": [],
            "password_resets": [],
            "cloudwatch_logs": []
        }
        self._load()

    def _load(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                self.save()
        else:
            self.save()

    def save(self):
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def get_collection_data(self, name: str) -> List[Dict[str, Any]]:
        if name not in self.data:
            self.data[name] = []
        return self.data[name]

    def set_collection_data(self, name: str, items: List[Dict[str, Any]]):
        self.data[name] = items

    def get_collection(self, name: str) -> LocalCollection:
        return LocalCollection(name, self)


# Singleton instance
_local_db = LocalDatabase(DB_FILE)

class DatabaseManager:
    """Provides access to MongoDB collections with transparent fallback."""
    def __init__(self):
        self.client = None
        self.db = None
        self.use_mongo = False

        if MONGODB_URI:
            try:
                from pymongo import MongoClient
                self.client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2000)
                # Verify connection
                self.client.admin.command('ping')
                self.db = self.client.get_database("account_security_db")
                self.use_mongo = True
                print("[DB] Connected successfully to live MongoDB instance.")
            except Exception as e:
                print(f"[DB] Could not connect to MongoDB ({e}). Falling back to local document store.")
                self.use_mongo = False

    def get_collection(self, collection_name: str):
        if self.use_mongo and self.db is not None:
            return self.db[collection_name]
        return _local_db.get_collection(collection_name)

    @property
    def users(self):
        return self.get_collection("users")

    @property
    def active_sessions(self):
        return self.get_collection("active_sessions")

    @property
    def security_events(self):
        return self.get_collection("security_events")

    @property
    def password_resets(self):
        return self.get_collection("password_resets")

    @property
    def cloudwatch_logs(self):
        return self.get_collection("cloudwatch_logs")

db = DatabaseManager()
