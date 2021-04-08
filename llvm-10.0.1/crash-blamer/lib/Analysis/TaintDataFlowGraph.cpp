//===- TaintDataFlowGraph.cpp - Tait data flow ----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintDataFlowGraph.h"

#define DEBUG_TYPE "taint-dfg"

void TaintDataFlowGraph::addNode(std::shared_ptr<Node> n) {
  for (auto itr = Nodes.begin(); itr != Nodes.end(); ++itr) {
    if ((*itr).get() == n.get()) return;
  }

  Nodes.push_back(n);
}

void TaintDataFlowGraph::addEdge(std::shared_ptr<Node> src,
                                 std::shared_ptr<Node> dest, EdgeType e_type) {
  addNode(src);
  addNode(dest);
  adjacencies[src.get()].push_back({dest.get(), e_type});
}

void TaintDataFlowGraph::updateLastTaintedNode(TaintInfo Op,
  std::shared_ptr<Node> N) {
  lastTaintedNode[Op] = N;
}

void TaintDataFlowGraph::getBlameFn() {
  // All nodes at the max level (with the max length up to deref edge).
  std::unordered_map<unsigned, llvm::SmallVector<Node *, 8>> blameNodes;
  unsigned maxLevel = 0;

  unsigned nodeReachedLvl = 0;
  for (auto &node : Nodes) {
    auto &NodeAdjs = adjacencies[node.get()];
    if (!NodeAdjs.size()) continue;

    for (auto &a : NodeAdjs) {
      auto &adjNode = a.first;
      auto &edgeType = a.second;
      if (edgeType == EdgeType::Dereference) {
        if (nodeReachedLvl > maxLevel) {
          maxLevel = nodeReachedLvl;
          blameNodes[maxLevel].push_back(adjNode);
        }
      } else {
        nodeReachedLvl++;
      }
    }
  }

  LLVM_DEBUG(llvm::dbgs() << "Blame Nodes:\n";
    StringRef BlameFn = "";
    auto &BlameNodes = blameNodes[maxLevel];
    for (auto &a : BlameNodes) {
      a->print();
      llvm::dbgs() << "\nBlame line: " << a->MI->getDebugLoc().getLine()
                   << "\n";
      if (BlameFn == "")
        BlameFn = a->MI->getMF()->getName();
      else {
        assert((BlameFn == a->MI->getMF()->getName()) &&
               "All blame nodes should come from the same fn.");
      }
    }
    llvm::dbgs() << "****Blame function: " << BlameFn << '\n';
  );
}

void TaintDataFlowGraph::dump() {
  LLVM_DEBUG(llvm::dbgs() << "\n\n === Taint Data Flow Graph === \n";
  llvm::dbgs() << "---> Assignment Edge; ***> Deref Edge \n";
  for (auto &node : Nodes) {
    auto &NodeAdjs = adjacencies[node.get()];
    if (!NodeAdjs.size()) continue;
    node->print();
    llvm::dbgs() << "\n";

    for (auto &a : NodeAdjs) {
      auto &adjNode = a.first;
      auto &edgeType = a.second;
      if (edgeType == EdgeType::Assigment)
        llvm::dbgs() << "  ---> ";
      else
        llvm::dbgs() << "  ***> ";
      adjNode->print();
      llvm::dbgs() << "\n";
    }
  }

  llvm::dbgs() << "\n";);
}
