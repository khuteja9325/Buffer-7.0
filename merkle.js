/**
 * ═══════════════════════════════════════════════════════════
 *   MerkleGuard — Core DSA Engine
 *   Merkle Tree File Integrity Monitor
 * ═══════════════════════════════════════════════════════════
 *
 *  Data Structures:
 *    - Binary Tree (MerkleNode)
 *    - HashMap (file registry)
 *    - Queue (BFS for display)
 *    - Recursive DFS (tamper detection, proof path)
 *
 *  Complexity:
 *    - Build:  O(n)
 *    - Detect: O(log n)
 *    - Proof:  O(log n)
 */

'use strict';

// ─────────────────────────────────────────────────────────
// SHA-256 using Web Crypto API (browser-native, no deps)
// ─────────────────────────────────────────────────────────
async function sha256(input) {
  const data = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input;
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Pair(left, right) {
  return sha256(left + right);
}

// ─────────────────────────────────────────────────────────
// MerkleNode — one node in the binary tree
// ─────────────────────────────────────────────────────────
class MerkleNode {
  constructor({ hash, filename = null, left = null, right = null, status = 'ok' }) {
    this.hash     = hash;       // SHA-256 hex string
    this.filename = filename;   // Only on leaf nodes
    this.left     = left;
    this.right    = right;
    this.status   = status;     // 'ok' | 'tampered' | 'added' | 'deleted'
  }

  isLeaf() {
    return this.left === null && this.right === null;
  }
}

// ─────────────────────────────────────────────────────────
// MerkleTree — full tree built from file hashes
// ─────────────────────────────────────────────────────────
class MerkleTree {
  constructor() {
    this.root   = null;
    this.leaves = [];     // MerkleNode[] — one per file
    this.depth  = 0;
  }

  // ── Build bottom-up from array of {filename, hash, status} ──────────
  async build(fileEntries) {
    if (!fileEntries || fileEntries.length === 0) {
      this.root = null; this.leaves = []; this.depth = 0;
      return;
    }

    // Create leaf nodes
    this.leaves = fileEntries.map(e => new MerkleNode({
      hash: e.hash,
      filename: e.filename,
      status: e.status || 'ok'
    }));

    let currentLevel = [...this.leaves];
    this.depth = 0;

    // Combine pairs bottom-up
    while (currentLevel.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : currentLevel[i]; // duplicate last if odd
        const parentHash = await sha256Pair(left.hash, right.hash);
        const parentStatus = (left.status !== 'ok' || right.status !== 'ok') ? 'tampered' : 'ok';
        const parent = new MerkleNode({
          hash: parentHash,
          left,
          right: (i + 1 < currentLevel.length) ? right : null,
          status: parentStatus
        });
        nextLevel.push(parent);
      }
      currentLevel = nextLevel;
      this.depth++;
    }

    this.root = currentLevel[0];
  }

  getRootHash() {
    return this.root ? this.root.hash : null;
  }

  // ── O(log n): Compare two trees, return list of tampered filenames ───
  // Uses recursive DFS — skips subtrees where hashes match
  findTamperedFiles(otherTree) {
    const tampered = [];
    this._compareNodes(this.root, otherTree ? otherTree.root : null, tampered);
    return tampered;
  }

  _compareNodes(nodeA, nodeB, result) {
    if (!nodeA) return;

    // Hashes match → entire subtree is clean, skip it (KEY OPTIMIZATION)
    if (nodeB && nodeA.hash === nodeB.hash) return;

    if (nodeA.isLeaf()) {
      result.push(nodeA.filename);
      return;
    }

    // Go deeper — O(log n) because we only descend into differing subtrees
    this._compareNodes(nodeA.left,  nodeB ? nodeB.left  : null, result);
    this._compareNodes(nodeA.right, nodeB ? nodeB.right : null, result);
  }

  // ── O(log n): Get proof path for a single file ──────────────────────
  // Returns array of {hash, side, label} from leaf to root
  getProofPath(filename) {
    const path = [];
    const found = this._findPath(this.root, filename, path, 'root');
    if (!found) return null;
    path.reverse();
    return path;
  }

  _findPath(node, filename, path, side) {
    if (!node) return false;

    if (node.isLeaf()) {
      if (node.filename === filename) {
        path.push({ hash: node.hash, side, label: node.filename, isLeaf: true });
        return true;
      }
      return false;
    }

    if (this._findPath(node.left, filename, path, 'left')) {
      path.push({ hash: node.hash, side, label: 'internal', isLeaf: false, isRoot: node === this.root });
      if (node.right) path.push({ hash: node.right.hash, side: 'right-sibling', label: 'sibling', isSibling: true });
      return true;
    }
    if (this._findPath(node.right, filename, path, 'right')) {
      path.push({ hash: node.hash, side, label: 'internal', isLeaf: false, isRoot: node === this.root });
      if (node.left) path.push({ hash: node.left.hash, side: 'left-sibling', label: 'sibling', isSibling: true });
      return true;
    }

    return false;
  }

  // ── BFS traversal — returns levels array for rendering ──────────────
  getLevels() {
    if (!this.root) return [];
    const levels = [];
    let queue = [this.root];
    while (queue.length) {
      levels.push([...queue]);
      const next = [];
      for (const node of queue) {
        if (node.left)  next.push(node.left);
        if (node.right) next.push(node.right);
      }
      queue = next;
    }
    return levels;
  }

  // ── Count internal nodes ─────────────────────────────────────────────
  countInternalNodes() {
    let count = 0;
    const dfs = (node) => {
      if (!node || node.isLeaf()) return;
      count++;
      dfs(node.left);
      dfs(node.right);
    };
    dfs(this.root);
    return count;
  }
}

// ─────────────────────────────────────────────────────────
// FileRegistry — HashMap: filename → {hash, content, status, size}
// ─────────────────────────────────────────────────────────
class FileRegistry {
  constructor() {
    this._map = new Map();         // O(1) lookup by filename
    this.baselineRoot = null;      // Trusted root hash
    this.currentTree  = null;
    this.baselineTree = null;
  }

  async addFile(filename, content) {
    const hash = await sha256(content);
    const size = new Blob([content]).size;
    this._map.set(filename, {
      filename,
      content,
      baselineHash: null,
      currentHash: hash,
      status: 'added',
      size,
      addedAt: Date.now()
    });
  }

  removeFile(filename) {
    this._map.delete(filename);
  }

  getFile(filename) {
    return this._map.get(filename);
  }

  getAllFiles() {
    return Array.from(this._map.values());
  }

  getFilenames() {
    return Array.from(this._map.keys()).sort();
  }

  async modifyFile(filename, newContent) {
    const entry = this._map.get(filename);
    if (!entry) return;
    entry.content = newContent;
    entry.currentHash = await sha256(newContent);
    entry.size = new Blob([newContent]).size;
  }

  // Take a snapshot — all current hashes become the baseline
  async takeBaseline() {
    for (const entry of this._map.values()) {
      entry.baselineHash = entry.currentHash;
      entry.status = 'ok';
    }
    await this._rebuildTree();
    this.baselineRoot = this.currentTree.getRootHash();
    this.baselineTree = this.currentTree; // same state
    return this.baselineRoot;
  }

  // Re-hash all files and compare to baseline
  async scan() {
    for (const entry of this._map.values()) {
      if (!entry.baselineHash) continue;
      if (entry.currentHash !== entry.baselineHash) {
        entry.status = 'tampered';
      } else {
        entry.status = 'ok';
      }
    }
    await this._rebuildTree();
    return this.currentTree.findTamperedFiles(this.baselineTree);
  }

  async _rebuildTree() {
    const entries = this.getFilenames().map(name => {
      const e = this._map.get(name);
      return { filename: name, hash: e.currentHash, status: e.status };
    });
    this.currentTree = new MerkleTree();
    await this.currentTree.build(entries);
  }

  getCurrentRoot() {
    return this.currentTree ? this.currentTree.getRootHash() : null;
  }

  getBaselineRoot() {
    return this.baselineRoot;
  }

  isCompromised() {
    if (!this.baselineRoot || !this.currentTree) return false;
    return this.baselineRoot !== this.currentTree.getRootHash();
  }

  size() {
    return this._map.size;
  }
}

// Export for use in ui.js
window.MerkleGuardEngine = {
  sha256,
  sha256Pair,
  MerkleNode,
  MerkleTree,
  FileRegistry
};
