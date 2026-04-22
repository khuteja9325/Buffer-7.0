# 🔐 MerkleGuard — File Integrity Monitor

A production-grade **Merkle Tree File Integrity Monitor** built for the Buffer DSA × Cybersecurity competition.

---

## 🚀 Quick Start

**No installation needed. Just open in your browser.**

```bash
# Option 1: Open directly
open index.html    # macOS
start index.html   # Windows

# Option 2: Serve locally (recommended for folder picker)
npx serve .        # then visit http://localhost:3000
# or
python -m http.server 8080
```

> ⚠️ The **"Open Real Folder"** button (File System Access API) requires a local server AND Chrome/Edge. Opening `index.html` directly may block it due to CORS.

---

## 📁 Project Structure

```
merkle-guard/
├── index.html      ← Main app shell (UI layout, all panels)
├── style.css       ← Full dark cybersecurity theme
├── merkle.js       ← Core DSA engine (Merkle Tree, SHA-256)
├── ui.js           ← UI controller (tabs, rendering, simulations)
└── README.md       ← This file
```

---

## 🧠 DSA Concepts Demonstrated

| Data Structure | Usage |
|---|---|
| **Binary Tree** | Core Merkle Tree — each node stores a SHA-256 hash |
| **HashMap (Map)** | `FileRegistry._map` — O(1) file lookup by name |
| **Queue (BFS)** | Tree level-by-level traversal for visualization |
| **DFS (Recursion)** | Tamper detection & proof path — O(log n) |
| **Array** | Leaf node construction before bottom-up build |

### Complexity
- **Build tree:** O(n) — hash every file, combine pairs upward
- **Detect tamper:** O(log n) — DFS skips entire clean subtrees
- **Verify one file:** O(log n) — only need sibling hashes up the path
- **Naive scan:** O(n) — Merkle trees are dramatically more efficient at scale

---

## ✨ Features

### Core
- ✅ SHA-256 file hashing (Web Crypto API — browser native, no dependencies)
- ✅ Merkle Tree built bottom-up from file hashes
- ✅ Root hash as single integrity fingerprint
- ✅ O(log n) tamper detection via recursive DFS
- ✅ Proof path visualization for any file

### UI
- ✅ Dark terminal aesthetic with animated boot screen
- ✅ Live SVG Merkle Tree that updates in real time
- ✅ Drag & drop file upload (any file type)
- ✅ Real folder access via File System Access API (Chrome/Edge)
- ✅ File table with search, filter, and status badges
- ✅ Interactive attack simulation lab (6 attack scenarios)
- ✅ Audit log with CSV export
- ✅ DSA notes / theory panel

### Attack Simulations
1. ⚡ **Byte Flip** — Flip 1 byte, root hash changes instantly
2. 💉 **Malicious Injection** — Inject unauthorized shell script
3. 🗑 **File Deletion** — Silently delete a critical file
4. 🕐 **Metadata Spoof** — Timestamp-only change (correctly ignored)
5. 💣 **Mass Compromise** — Ransomware-style 50% file encryption
6. 👑 **Root Substitution** — Attacker tries to fake the root hash

---

## 🌐 Real Folder Access

Click **"Open Real Folder (Chrome/Edge)"** to monitor your actual local files:
1. Uses the **File System Access API** (browser standard)
2. You grant read-only permission via the OS file picker
3. Files are hashed in the browser — nothing is sent to any server
4. Works on Chrome 86+ and Edge 86+

---

## 🏆 Competition Angle

This project demonstrates **all DSA pillars** the judges care about:

- **Hashing:** SHA-256 on every file (raw bytes, works for any format)
- **Binary Tree:** Full Merkle Tree implementation from scratch
- **Tree Traversal:** BFS for rendering, DFS for detection
- **Algorithm Efficiency:** O(log n) vs O(n) — visualized with real numbers
- **Real-world DSA:** Same structure as Bitcoin, Git, and IPFS

---

## 🛠 Tech Stack

| Layer | Tech |
|---|---|
| Hashing | Web Crypto API (SubtleCrypto SHA-256) |
| DSA | Vanilla JS classes (no libraries) |
| UI | Pure HTML/CSS/JS (no frameworks) |
| Font | DM Sans + Space Mono (Google Fonts) |

Zero dependencies. Zero build step. Just open and run.
