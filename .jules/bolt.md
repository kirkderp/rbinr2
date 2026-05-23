## 2024-05-23 - Performance Optimization in DashMap

**Learning:** When removing items from a `DashMap` based on a predicate, iterating to collect keys into a `Vec` and then looping to remove them is inefficient. It allocates a new `Vec` and requires re-hashing the keys for each removal.
**Action:** Use `DashMap::retain` instead. It mutates the map in-place, filtering out items that don't match the predicate, which avoids the intermediate allocation, reduces iteration passes, and avoids re-hashing. It's also safer for concurrent use cases.
