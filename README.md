

# 1. Project Title

MerkleGuard – File Integrity Monitor

---

# 2. Problem Statement

In modern systems, data is stored as collections of files within folders. Ensuring the integrity of these files is critical for security, especially in servers, applications, and distributed environments.

Traditional approaches verify integrity by checking each file individually, which leads to **O(n) time complexity**. As the number of files increases, this becomes inefficient and does not scale well.

The objective is to design a system that can:

* Efficiently verify large datasets
* Detect unauthorized modifications
* Reduce verification time complexity
* Provide clear traceability of changes

---

# 3. Team Number

135

---

# 4. Team Members

Team Thrivers

* Member 1: Khuteja Sheikh
* Member 2: Gauri Sahu
* Member 3: Asawari Chavan
* Member 4: Shravani Fale

---

# 5. Technologies Used

* HTML, CSS, JavaScript frontend
* Web Crypto API SHA-256 hashing
* Merkle Tree DSA logic
* Browser File System Access API

---

# 6. Features

* Folder upload multiple files
* SHA-256 hashing per file
* Merkle Tree construction
* Single root hash verification
* Logarithmic time verification process
* Real-time tamper detection system
* Attack simulation for testing
* Audit logs with timestamps
* Export logs as CSV
* Statistics and analytics dashboard
* Proof path for each file

---

# 7. How Project Works

1. Upload folder with files
2. Generate hash for each file
3. Build tree from hashes
4. Store root as baseline
5. Run scan for verification
6. Compare current and baseline root
7. Locate modified file efficiently
8. Record actions in audit log
9. Visualize data using statistics

---

# 8. Future Scope

* Real-time continuous monitoring system
* Cloud storage integration support
* Distributed verification using nodes
* Automated alert notification system
* Optimization for large datasets

---
