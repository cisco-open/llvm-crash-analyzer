//===- TaintDataFlowGraph.cpp - Tait data flow ----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintDataFlowGraph.h"

#include "llvm/IR/DebugInfoMetadata.h"

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

// Using DFS.
void TaintDataFlowGraph::findBlameFunction(Node *v, unsigned level) {
  visited[v] = true;
  level++;

  auto &NodeAdjs = adjacencies[v];
  if (!NodeAdjs.size()) return;

  for (auto &a : NodeAdjs) {
    auto &adjNode = a.first;
    if (!visited[adjNode]) {
      auto &edgeType = a.second;
      if (edgeType == EdgeType::Dereference) {
        if (level > MaxLevel) {
          MaxLevel = level;
          blameNodes[MaxLevel].push_back(adjNode);
        }
      }
      findBlameFunction(adjNode, level);
    }
 }
}

bool TaintDataFlowGraph::printBlameFunction() {
    bool Res = false;
    LLVM_DEBUG(llvm::dbgs() << "Blame Nodes:\n";
    StringRef BlameFn = "";
    const MachineFunction *MF = nullptr;
    auto &BlameNodes = blameNodes[MaxLevel];
    for (auto &a : BlameNodes) {
      a->print();
      if (a->MI->getDebugLoc().get())
        llvm::dbgs() << "\nBlame line: " << a->MI->getDebugLoc().getLine()
                     << "\n";
      else
        llvm::dbgs() << "\nNo blame line to report.\n";

      if (BlameFn == "") {
        BlameFn = a->MI->getMF()->getName();
        MF = a->MI->getMF();
      } else {
        assert((BlameFn == a->MI->getMF()->getName()) &&
               "All blame nodes should come from the same fn.");
      }
    }
    if (MF) {
      llvm::dbgs() << "\n****Blame function: " << BlameFn << '\n';
      if (MF->getFunction().getSubprogram())
        llvm::dbgs() << "****From file: " <<
          MF->getFunction().getSubprogram()->getFile()->getFilename() << "\n";
    }
  );

  StringRef BlameFn = "";
  const MachineFunction *MF = nullptr;
  auto &BlameNodes = blameNodes[MaxLevel];
  for (auto &a : BlameNodes) {
    if (BlameFn == "") {
      BlameFn = a->MI->getMF()->getName();
      MF = a->MI->getMF();
    } else {
      assert((BlameFn == a->MI->getMF()->getName()) &&
             "All blame nodes should come from the same fn.");
    }
  }

  if (MF) {
    llvm::outs() << "\nBlame Function is " << BlameFn << '\n';
    if (MF->getFunction().getSubprogram())
      llvm::outs() << "From File " <<
        MF->getFunction().getSubprogram()->getFile()->getFilename() << "\n";
    Res = true;
  } else {
    llvm::outs() << "Failed to find Blame function\n";
  }

  return Res;
}

void TaintDataFlowGraph::dump() {
  LLVM_DEBUG(llvm::dbgs() << "\n\n === Taint Data Flow Graph === \n";
  llvm::dbgs() << "---> Assignment Edge; ***> Deref Edge \n";
  for (auto &node : Nodes) {
    if (!node)
      continue;
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
