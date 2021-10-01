//===- TaintDataFlowGraph.cpp - Tait data flow ----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Analysis/TaintDataFlowGraph.h"

#include "llvm/IR/DebugInfoMetadata.h"

#include "llvm/Support/raw_ostream.h"

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

void MFProgramPointInfo::traverseForLevels(
    const MachineBasicBlock* MBB, unsigned level) {
  visitedMBBs[MBB] = true;
  mbbLevels[MBB] = level;

  // FIXME: Can we have multiple MIs performing deref edge?
  // if that is the case we need to consider MIs inside BB
  // into levels.

  if (MBB->succ_empty())
    return;

  level++;
  for (const MachineBasicBlock *Succ : MBB->successors()) {
    if (!visitedMBBs[Succ])
      traverseForLevels(Succ, level);
  }
}

void MFProgramPointInfo::dump() {
  LLVM_DEBUG(
    llvm::dbgs() << "*** MFProgramPointInfo ***\n";
    for (const auto &n : mbbLevels) {
        llvm::dbgs() << "bb." << n.first->getNumber() << ": " << n.second << "\n";
    });
}

void TaintDataFlowGraph::countLevels(const MachineFunction* MF) {
  MFProgramPointInfo lvlInfo;

  const MachineBasicBlock* EntryBB = &(*(MF->begin()));
  lvlInfo.traverseForLevels(EntryBB, 0);

  levels[MF] = lvlInfo;

  // Calculate dominators so we can report right blame line.
  MachineDominatorTree *MDT =
      new MachineDominatorTree(*(const_cast<MachineFunction*>(MF)));
  dominators[MF] = MDT;
}

// Using DFS.
void TaintDataFlowGraph::findBlameFunction(Node *v) {
  visited[v] = true;

  auto &NodeAdjs = adjacencies[v];
  if (!NodeAdjs.size()) return;

  for (auto &a : NodeAdjs) {
    auto &adjNode = a.first;
    if (!visited[adjNode]) {
      auto &edgeType = a.second;
      if (edgeType == EdgeType::Dereference) {
        // Check the level.
        auto *MI = adjNode->MI;
        auto MF = MI->getMF();
        if (!levels.count(MF)) {
          countLevels(MF);
          LLVM_DEBUG(llvm::dbgs() << "Fn " << MF->getName() << "\n";);
          levels[MF].dump();
        }
        unsigned bbLevel = levels[MF].mbbLevels[MI->getParent()];
        BlameLevel currLvl{adjNode->frameNum, bbLevel};
        if (currLvl > MaxLevel || currLvl == MaxLevel) {
          if (currLvl == MaxLevel) {
            // If two nodes comes from the same basic block
            // we should consider dominating instruction as
            // the one responsible for loading bad value.
            auto *MDT = dominators[adjNode->MI->getMF()];
            auto &BlameNodes = blameNodes[MaxLevel];
            for (unsigned i = 0; i < BlameNodes.size(); i++) {
              auto &a = BlameNodes[i];
              if (a->MI->getParent() == adjNode->MI->getParent()) {
                if (MDT->dominates(adjNode->MI, a->MI)) {
                  BlameNodes.erase(BlameNodes.begin() + i);
                  break;
                }
              }
            }
          }
          MaxLevel = currLvl;
          blameNodes[MaxLevel].push_back(adjNode);
        }
      }
      findBlameFunction(adjNode);
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

  if (!MF) {
    llvm::outs() << "Failed to find Blame function\n";
    return Res;
  }

  llvm::outs() << "\nBlame Function is " << BlameFn << '\n';
  if (MF->getFunction().getSubprogram())
    llvm::outs() << "From File " <<
      MF->getFunction().getSubprogram()->getFile()->getFilename() << "\n";
  Res = true;

  // Delete all the MDT info, since we don't need it anymore.
  for (auto &mdt : dominators) {
    delete mdt.second;
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

void TaintDataFlowGraph::printAsDOT(std::string fileName) {
  std::error_code EC;
  raw_fd_ostream MyDotFile{fileName, EC, sys::fs::OF_Text};

  if (EC) {
    llvm::errs() << "Could not open file: " << EC.message() << ", " << fileName
                 << '\n';
    return;
  }

  MyDotFile << "digraph TaintDataFlowGraph {\n";

  for (auto &node : Nodes) {
    if (!node) continue;
    auto &NodeAdjs = adjacencies[node.get()];
    if (!NodeAdjs.size()) continue;

    for (auto &a : NodeAdjs) {
      if (node->IsCrashNode) {
        MyDotFile << " crashNode";
      } else {
        MyDotFile << " \"{";
        if (node->MI) {
          MyDotFile << node->MI->getParent()->getParent()->getCrashOrder()
                    << "; ";
          node->MI->print(MyDotFile, /*IsStandalone*/ true,
                          /*SkipOpers*/ false, /*SkipDebugLoc*/ true,
                          /*AddNewLine*/ false);
        } else {
          MyDotFile << "unknown MI";
        }
        MyDotFile << "; ";
        MyDotFile << " ";
        if (node->TaintOp.Op) {
          if (node->IsContant) {
            MyDotFile << "CONSTANT: ";
            MyDotFile << *(node->TaintOp.Op);
          } else if (node->TaintOp.IsConcreteMemory) {
            MyDotFile << "MEM: ";
            MyDotFile << node->TaintOp.GetTaintMemAddr();
          } else {
            MyDotFile << "REG: ";
            MyDotFile << *(node->TaintOp.Op);
          }
        } else
          MyDotFile << "unknown taint operand";
        MyDotFile << "}\"";
      }

      auto &adjNode = a.first;
      auto &edgeType = a.second;
      MyDotFile << "  -> ";

      if (adjNode->IsCrashNode) {
        MyDotFile << " crashNode";
      } else {
        MyDotFile << " \"{";
        if (adjNode->MI) {
          MyDotFile << adjNode->MI->getParent()->getParent()->getCrashOrder()
                    << "; ";
          adjNode->MI->print(MyDotFile, /*IsStandalone*/ true,
                             /*SkipOpers*/ false, /*SkipDebugLoc*/ true,
                             /*AddNewLine*/ false);
        } else {
          MyDotFile << "unknown MI";
        }
        MyDotFile << "; ";
        MyDotFile << " ";
        if (adjNode->TaintOp.Op) {
          if (adjNode->IsContant) {
            MyDotFile << "CONSTANT: ";
            MyDotFile << *(adjNode->TaintOp.Op);
          } else if (adjNode->TaintOp.IsConcreteMemory) {
            MyDotFile << "MEM: ";
            MyDotFile << adjNode->TaintOp.GetTaintMemAddr();
          } else {
            MyDotFile << "REG: ";
            MyDotFile << *(adjNode->TaintOp.Op);
          }
        } else
          MyDotFile << "unknown taint operand";
        MyDotFile << "}\"";
      }

      if (edgeType == EdgeType::Dereference) MyDotFile << " [color=\"red\"]";

      MyDotFile << ";\n";
    }
  }

  MyDotFile << "}\n";
}
