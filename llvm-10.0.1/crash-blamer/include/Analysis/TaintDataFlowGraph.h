//===- TaintDataFlowGraph.h - Tait data flow ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef TDFG_
#define TDFG_

#include "Analysis/TaintAnalysis.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"

#include <memory>

using namespace llvm;
using namespace crash_blamer;

// Triple to unify a node in backward graph.
struct Node {
  unsigned frameNum;
  const MachineInstr *MI;
  TaintInfo TaintOp;
  unsigned ID;
  static unsigned NextID;
  bool IsCrashNode;
  bool IsContant;

  Node(unsigned f, const MachineInstr *I, TaintInfo T, bool b,
       bool isCnst = false)
      : frameNum(f), MI(I), TaintOp(T), ID(NextID++),
      IsCrashNode(b), IsContant(isCnst) {}

  unsigned getID() const { return ID; }

  void print() {
    if (IsCrashNode) {
      llvm::dbgs() << "{crash-node}";
    } else {
      unsigned id = getID();
      llvm::dbgs() << "!" << id;
      llvm::dbgs() << "{" << frameNum << "; ";
      if (MI)
        MI->print(llvm::dbgs(), /*IsStandalone*/ true, /*SkipOpers*/ false,
                  /*SkipDebugLoc*/ true, /*AddNewLine*/ false);
      else
        llvm::dbgs() << "unknown MI\n";

      llvm::dbgs() << "; ";
      if (TaintOp.Op) {
        if (IsContant) {
          llvm::dbgs() << "CONSTANT: ";
          llvm::dbgs() << *TaintOp.Op;
        } else if (TaintOp.IsConcreteMemory) {
          llvm::dbgs() << "MEM: ";
          llvm::dbgs() << "CONCRETE MEM ADDRESS";
        } else {
          llvm::dbgs() << "REG: ";
          llvm::dbgs() << *TaintOp.Op;
        }
      } else
        llvm::dbgs() << "unknown taint operand\n";

      llvm::dbgs() << "}";
    }
  }
};

// Mark edge type.
enum class EdgeType {
  Assigment /* represented with ---> */,
  Dereference /* represented with ***> */
};

using EdgeToNode = std::pair<Node *, EdgeType>;

// Backward Data Flow Graph.
class TaintDataFlowGraph {
  // All nodes.
  SmallVector<std::shared_ptr<Node>, 8> Nodes;

  // Represents adjacence map.
  std::map<Node *, SmallVector<EdgeToNode, 8>> adjacencies;

  // Used for graph algorithms.
  std::map<Node *, bool> visited;

  // Used for finding blame node.
  std::unordered_map<unsigned, llvm::SmallVector<Node *, 8>> blameNodes;

  unsigned MaxLevel = 0;

 public:
  // Map operand to the latest taint node.
  // FIXME: This should be private.
  std::map<TaintInfo, std::shared_ptr<Node>> lastTaintedNode;

  void addEdge(std::shared_ptr<Node> src, std::shared_ptr<Node> dest,
               EdgeType e_type = EdgeType::Assigment);
  void addNode(std::shared_ptr<Node> n);

  void updateLastTaintedNode(TaintInfo Op,
                             std::shared_ptr<Node> N);
  unsigned getBlameNodesSize() { return Nodes.size(); }

  Node *getCrashNode() { return Nodes[0].get(); }

  void findBlameFunction(Node *v, unsigned level);
  bool printBlameFunction();

  void dump();
};

#endif
