
# Runtime optimization hook for PyInstaller
import os
import sys
import threading

# Disable unnecessary warnings and outputs
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Lazy import optimization
class LazyImporter:
    def __init__(self, modules_dict):
        self.modules = modules_dict
        self._imported = {}
    
    def __getattr__(self, name):
        if name in self.modules and name not in self._imported:
            module_name = self.modules[name]
            self._imported[name] = __import__(module_name, fromlist=['*'])
        return self._imported[name]

# Preload commonly used modules in a background thread
def preload_modules():
    try:
        import importlib
        modules_to_preload = ['webview', 'cryptography', 'tkinter']
        for module in modules_to_preload:
            try:
                importlib.import_module(module)
            except:
                pass
    except:
        pass

# Start preloading in background to avoid blocking the main thread
threading.Thread(target=preload_modules, daemon=True).start()

# Optimize file system access for resource loading
def optimize_resource_loading():
    base_dir = getattr(sys, '_MEIPASS', os.path.abspath('.'))
    resource_files = ['index.html', 'style.css', 'script.js', 'favi.png']
    
    # Create in-memory cache for resource paths
    global _resource_cache
    _resource_cache = {}
    
    for filename in resource_files:
        path = os.path.join(base_dir, filename)
        if os.path.exists(path):
            _resource_cache[filename] = path

optimize_resource_loading()

# Patch the resource_path function for faster lookups
original_resource_path = None
if 'resource_path' in globals():
    original_resource_path = globals()['resource_path']

def optimized_resource_path(relative_path):
    if relative_path in _resource_cache:
        return _resource_cache[relative_path]
    
    if original_resource_path:
        return original_resource_path(relative_path)
    
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    
    result = os.path.join(base_path, relative_path)
    _resource_cache[relative_path] = result
    return result

# Replace with optimized version
globals()['resource_path'] = optimized_resource_path
