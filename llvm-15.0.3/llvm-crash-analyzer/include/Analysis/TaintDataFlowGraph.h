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
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"

#include <memory>
#include <string>
#include <algorithm>

using namespace llvm;
using namespace crash_analyzer;

// Triple to unify a node in backward graph.
struct Node {
  unsigned frameNum;
  const MachineInstr *MI;
  TaintInfo TaintOp;
  unsigned ID;
  static unsigned NextID;
  bool IsCrashNode;
  bool IsContant;
  unsigned Depth = 0;

  // Call instruction that performed the call to function that is out
  // of bt.
  const MachineInstr *CallMI = nullptr;

  Node(unsigned f, const MachineInstr *I, TaintInfo T, bool b,
       bool isCnst = false)
      : frameNum(f), MI(I), TaintOp(T), ID(NextID++), IsCrashNode(b),
        IsContant(isCnst) {}

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
          llvm::dbgs() << TaintOp.GetTaintMemAddr();
        } else if (TaintOp.Offset) {
          llvm::dbgs() << "MEM: ";
          llvm::dbgs() << *TaintOp.Op;
          llvm::dbgs() << " + ";
          llvm::dbgs() << *TaintOp.Offset;
        } else {
          llvm::dbgs() << "REG: ";
          llvm::dbgs() << *TaintOp.Op;
        }
        llvm::dbgs() << "; DEREF-LVL: " << TaintOp.DerefLevel;
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

// This class marks levels of program points for functions
// from bt.
// E.g.: mbb lvl 1, mi num 4 is one level.
struct MFProgramPointInfo {
  std::unordered_map<const MachineBasicBlock *, unsigned> mbbLevels;
  // std::unordered_map<const MachineInstr*, unsigned> instrLevels;

  std::map<const MachineBasicBlock *, bool> visitedMBBs;
  void traverseForLevels(const MachineBasicBlock *MBB, unsigned level);
  void dump();
};

using EdgeToNode = std::pair<Node *, EdgeType>;

// Backward Data Flow Graph.
class TaintDataFlowGraph {
  llvm::DenseMap<const MachineFunction *, MFProgramPointInfo> levels;

  // All nodes.
  SmallVector<std::shared_ptr<Node>, 8> Nodes;

  // Represents adjacence map.
  std::map<Node *, SmallVector<EdgeToNode, 8>> adjacencies;

  // Used for graph algorithms.
  std::map<Node *, bool> visited;

  DenseMap<const MachineFunction *, MachineDominatorTree *> dominators;

  struct BlameLevel {
    unsigned fnLevel;
    unsigned bbLevel;

    BlameLevel() = default;
    BlameLevel(unsigned f, unsigned bbLevel_) : fnLevel(f), bbLevel(bbLevel_) {}

    bool operator==(const BlameLevel &l) const {
      if (fnLevel != l.fnLevel)
        return false;

      if (bbLevel != l.bbLevel)
        return false;

      return true;
    }
    bool operator>(const BlameLevel &l) const {
      if (fnLevel > l.fnLevel)
        return true;
      if (fnLevel < l.fnLevel)
        return false;

      return bbLevel < l.bbLevel;
    }
  };

  BlameLevel MaxLevel{0, UINT32_MAX};

  struct hash_fn {
    std::size_t operator()(const BlameLevel &l) const {
      std::size_t h1 = std::hash<unsigned>()(l.fnLevel);
      std::size_t h2 = std::hash<unsigned>()(l.bbLevel);
      return h1 ^ h2;
    }
  };

  // Used for finding blame node.
  std::unordered_map<BlameLevel, llvm::SmallVector<Node *, 8>, hash_fn>
      blameNodes;

public:
  // Map operand to the latest taint node.
  // FIXME: This should be private.
  std::map<const MachineOperand*, std::shared_ptr<Node>> lastTaintedNode;

  void addEdge(std::shared_ptr<Node> src, std::shared_ptr<Node> dest,
               EdgeType e_type = EdgeType::Assigment);
  void addNode(std::shared_ptr<Node> n);

  void updateLastTaintedNode(const MachineOperand* Op, std::shared_ptr<Node> N);
  unsigned getBlameNodesSize() { return Nodes.size(); }

  Node *getCrashNode() { return Nodes[0].get(); }

  void findBlameFunction(Node *v);
  bool printBlameFunction(bool PrintPotentialCrashCauseLocation);

  void countLevels(const MachineFunction *MF);

  void dump();
  void printAsDOT(std::string fileName, bool Verbose = false);
};

#endif
