//===- ConcreteReverseExec.h - Concrete Reverse Execution -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef CRE_
#define CRE_

#include "Analysis/TaintAnalysis.h"
#include "Analysis/RegisterEquivalence.h"
#include "Target/CATargetInfo.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstr.h"

#include <tuple>
#include <unordered_map>

using namespace llvm;
using namespace crash_analyzer;

// Class that implements the Concrete Reverse Execution.
// TODO: Since we rely on corefile content during CRE and TA,
// by updating register values, we need to remember changes
// to memory as well, since there could be instructions
// that may store.
class ConcreteReverseExec {
  // This represents current values in the registers.
  MachineFunction::RegisterCrashInfo currentRegisterValues;
  const MachineFunction *mf;
  MemoryWrapper& MemWrapper;
  RegisterEquivalence* REAnalysis;

  CATargetInfo *CATI;

  // Functions that are out of BT don't have any register value information
  // in corefiles, so we have nothing to start with.
  // FIXME: Should we propagate some values from previos frame?
  bool CREEnabled = false;

public:
  // Init the curr reg values with the values from the 'regInfo' attribute,
  // which are the values read from corefile.
  ConcreteReverseExec(const MachineFunction *MF, MemoryWrapper& MW, RegisterEquivalence *REAnalysis = nullptr)
      : currentRegisterValues(MF->getCrashRegInfo()), mf(MF), MemWrapper(MW), REAnalysis(REAnalysis)  {
    CATI = getCATargetInfoInstance();
    if (MF->getCrashRegInfo().size())
      CREEnabled = true;
  }
  void dump();
  // FIXME: This is used for debugging purposes only -- DELETEME.
  void dump2();
  void updateCurrRegVal(std::string Reg, std::string Val);
  void updatePC(const MachineInstr &MI);
  void writeUIntRegVal(std::string Reg, uint64_t Val, unsigned regValSize = 16);
  void invalidateRegVal(std::string Reg);
  std::string getCurretValueInReg(const std::string &Reg);

  CATargetInfo *getCATargetInfo() { return CATI; }

  const MachineFunction *getMF() { return mf; }
  bool getIsCREEnabled() const;

  // Reverse execution of the MI by updating the currentRegisterValues.
  void execute(const MachineInstr &MI);

  std::string getEqRegValue(MachineInstr* MI, Register& Reg, const TargetRegisterInfo& TRI);
};

#endif
