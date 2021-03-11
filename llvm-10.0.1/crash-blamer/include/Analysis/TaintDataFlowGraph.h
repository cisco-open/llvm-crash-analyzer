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
  bool IsCrashNode;
  bool IsContant;

  Node(unsigned f, const MachineInstr *I, TaintInfo T, bool b,
       bool isCnst = false)
      : frameNum(f), MI(I), TaintOp(T), IsCrashNode(b), IsContant(isCnst) {}

  void print() {
    if (IsCrashNode) {
      llvm::dbgs() << "{crash-node}";
    } else {
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

 public:
  // Map operand to the latest taint node.
  // FIXME: This should be private.
  std::map<TaintInfo, std::shared_ptr<Node>> lastTaintedNode;

  void addEdge(std::shared_ptr<Node> src, std::shared_ptr<Node> dest,
               EdgeType e_type = EdgeType::Assigment);
  void addNode(std::shared_ptr<Node> n);

  void updateLastTaintedNode(TaintInfo Op,
                             std::shared_ptr<Node> N);

  void getBlameFn();
  void dump();
};

#endif
