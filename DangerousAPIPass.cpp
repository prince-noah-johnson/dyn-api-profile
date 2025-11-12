//===- DangerousAPIPass.cpp - Instrument dangerous API calls --------------===//
//
// LLVM Pass to instrument strcpy calls for dynamic profiling
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

struct DangerousAPIPass : public PassInfoMixin<DangerousAPIPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    bool Modified = false;
    LLVMContext &Ctx = M.getContext();
    
    // Get or declare the profiling function in the runtime library
    // void profiling_log(const char* api_name, const char* caller_name)
    Type *Int8PtrTy = PointerType::getUnqual(Ctx);
    
    FunctionType *LogFuncType = FunctionType::get(
        Type::getVoidTy(Ctx),
        ArrayRef<Type*>({Int8PtrTy, Int8PtrTy}),
        false
    );
    
    FunctionCallee LogFunc = M.getOrInsertFunction("profiling_log", LogFuncType);
    
    // List of dangerous APIs to instrument (starting with strcpy)
    std::vector<std::string> DangerousAPIs = {"strcpy"};
    
    // Iterate through all functions in the module
    for (Function &F : M) {
      if (F.isDeclaration()) continue; // Skip declarations
      
      // Store instructions to instrument (can't modify while iterating)
      std::vector<CallInst*> CallsToInstrument;
      
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          if (auto *CI = dyn_cast<CallInst>(&I)) {
            Function *CalledFunc = CI->getCalledFunction();
            
            // Check if this is a direct call to a dangerous API
            if (CalledFunc && !CalledFunc->isIntrinsic()) {
              std::string CalledName = CalledFunc->getName().str();
              
              // Check if it's in our dangerous API list
              for (const auto &API : DangerousAPIs) {
                if (CalledName == API) {
                  CallsToInstrument.push_back(CI);
                  break;
                }
              }
            }
          }
        }
      }
      
      // Now instrument the collected calls
      for (CallInst *CI : CallsToInstrument) {
        IRBuilder<> Builder(CI);
        
        // Create string constants for API name and caller function name
        Value *APIName = Builder.CreateGlobalStringPtr(
            CI->getCalledFunction()->getName()
        );
        Value *CallerName = Builder.CreateGlobalStringPtr(F.getName());
        
        // Insert call to profiling_log BEFORE the dangerous API call
        Builder.CreateCall(LogFunc, {APIName, CallerName});
        
        Modified = true;
        
        errs() << "Instrumented " << CI->getCalledFunction()->getName() 
               << " in function " << F.getName() << "\n";
      }
    }
    
    return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  
  static bool isRequired() { return true; }
};

} // end anonymous namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getDangerousAPIPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DangerousAPIPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "dangerous-api-pass") {
                    MPM.addPass(DangerousAPIPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getDangerousAPIPassPluginInfo();
}