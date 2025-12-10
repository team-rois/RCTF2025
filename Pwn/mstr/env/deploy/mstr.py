import ctypes

from typing import Union, List, Dict

STRPTR_OFFSET = 0x28 
LENPTR_OFFSET = 0x10

class MutableStr:
    pass

class MutableStr:
    def __init__(self, data:str):
        self.data = data
        self.base_ptr = id(self.data)
        self.max_size_str = ""

    def set_max_size(self, max_size_str):
        if int(max_size_str) < ((len(self)+7) & ~7):
            self.max_size_str = max_size_str
        else:
            print("can't set max_size: too big")

    def __repr__(self):
        return self.data

    def __str__(self):
        return self.__repr__()        

    def __len__(self):
        if self.base_ptr is None:
            return 0
        ptr = ctypes.cast(self.base_ptr + LENPTR_OFFSET, ctypes.POINTER(ctypes.c_int64))
        return ptr[0]
    
    def __getitem__(self, key:int):
        if not isinstance(key, int):
            raise NotImplementedError
        if key >= len(self) or key < 0:
            raise RuntimeError("get overflow")
        
        return self.data[key]

    def __setitem__(self, key:int, value:int):
        if not isinstance(value, int):
            raise NotImplementedError("only support integer value")

        if not isinstance(key, int):
            raise NotImplementedError("only support integer key")

        if key >= len(self) or key < 0:
            raise RuntimeError(f"set overflow: length:{len(self)}, key:{key}")
        
        strptr = ctypes.cast(self.base_ptr + STRPTR_OFFSET, ctypes.POINTER(ctypes.c_char))
        strptr[key] = value
    
    def __add__(self, other:Union[str,MutableStr]):
        if isinstance(other, str):
            return MutableStr(self.data + other)
        
        if isinstance(other, MutableStr):
            return MutableStr(self.data + other.data)
        
        raise NotImplementedError()
    
    def _add_str(self, other):
        if self.max_size_str == "":
            max_size = (len(self)+7) & ~7
        else:
            max_size = int(self.max_size_str)
        if len(self)+len(other) <= max_size:
            other_len = len(other)
            strptr = ctypes.cast(self.base_ptr + STRPTR_OFFSET, ctypes.POINTER(ctypes.c_char))
            otherstrptr = ctypes.cast(id(other) + STRPTR_OFFSET, ctypes.POINTER(ctypes.c_char))
            for i in range(other_len):
                strptr[i+len(self)] = otherstrptr[i]
            if len(self)+other_len < max_size:
                # strptr[len(self)+other_len] = 0 
                pass
            ctypes.cast(self.base_ptr + LENPTR_OFFSET, ctypes.POINTER(ctypes.c_int64))[0] += other_len
        else:
            print("Full!")
        return self
    
    def __iadd__(self, other):
        if isinstance(other, str):
            return self._add_str(other)
        if isinstance(other, MutableStr):
            return self._add_str(other.data)
        return self

def new_mstring(data:str) -> MutableStr:
    return MutableStr(data)

mstrings:List[MutableStr] = []

def main():
    while True:
        try:
            cmd, data, *values = input("> ").split()
            if cmd == "new":
                mstrings.append(new_mstring(data))
            
            if cmd == "set_max":
                idx = int(values[0])
                if idx >= len(mstrings) or idx < 0:
                    print("invalid index")
                    continue
                mstrings[idx].set_max_size(data)
            
            if cmd == "+":
                idx1 = int(data)
                idx2 = int(values[0])
                if idx1 < 0 or idx1 >= len(mstrings) or idx2 < 0 or idx2 >= len(mstrings):
                    print("invalid index")
                    continue
                mstrings.append(mstrings[idx1]+mstrings[idx2])

            if cmd == "+=":
                idx1 = int(data)
                idx2 = int(values[0])
                if idx1 < 0 or idx1 >= len(mstrings) or idx2 < 0 or idx2 >= len(mstrings):
                    print("invalid index")
                    continue
                mstrings[idx1] += mstrings[idx2]

            if cmd == "print_max":
                idx = int(data)
                if idx >= len(mstrings) or idx < 0:
                    print("invalid index")
                    continue
                print(mstrings[idx].max_size_str)

            if cmd == "print":
                idx = int(data)
                if idx >= len(mstrings) or idx < 0:
                    print("invalid index")
                    continue
                print(mstrings[idx].data)

            if cmd == "modify":
                idx = int(data)
                offset = int(values[0])
                val = values[1]
                
                if idx >= len(mstrings) or idx < 0:
                    print("invalid index")
                    continue
                mstrings[idx][offset] = int(val)
        except EOFError:
            break
        except Exception as e:
            print(f"error: {e}")

print("hello!", flush=True)
main()
