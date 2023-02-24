
import shelve
import hashlib
import angr

class AngrProjectCache(shelve.DbfilenameShelf[angr.Project]):
    @staticmethod
    def _hash_file(path:str, bufsize=65535):
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            b = f.read(bufsize)
            while len(b) > 0:
                h.update(b)
                b = f.read(bufsize)
        
        return h.hexdigest()

    def lookup(self, filepath:str, default=None):
        filehash = self._hash_file(filepath)
        return self.get(filehash, default)
        
    def cache_project(self, filepath:str, project:angr.Project):
        filehash = self._hash_file(filepath)
        self[filehash] = project

    def invalidate(self, filepath:str):
        filehash = self._hash_file(filepath)
        del self[filehash]

    def is_cached(self, filepath:str):
        filehash = self._hash_file(filepath)
        return filehash in self

    def create_if_not_cached(self, filepath:str, *args, **kwargs):
        filehash = self._hash_file(filepath)
        project = self.get(filehash)
        if project is None:
            project = angr.Project(filepath, *args, **kwargs)
            
        self[filehash] = project
        return project