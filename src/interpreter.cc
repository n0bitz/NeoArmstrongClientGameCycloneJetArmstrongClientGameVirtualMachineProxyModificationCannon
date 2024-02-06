#include <bit>
#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <initializer_list>
#include <stdexcept>
#include <vector>

using std::vector;

// NTODO: alias type_t stuff as qvmType (eg. qvmInt, qvmFloat, ...)
using float32_t = float;
static_assert(sizeof(float32_t) * CHAR_BIT == 32, "unsupported platform");

namespace {

inline uint8_t GetUint8(const uint8_t** buf) { return ((*buf)++)[0]; }

inline uint32_t GetUint32(const uint8_t** buf) {
    // NTODO: constexpr branch to just reinterpret_cast on LE platforms?
    uint32_t x = static_cast<uint32_t>((*buf)[0]) |
                 static_cast<uint32_t>((*buf)[1]) << 8 |
                 static_cast<uint32_t>((*buf)[2]) << 16 |
                 static_cast<uint32_t>((*buf)[3]) << 24;
    *buf += 4;
    return x;
}

}  // namespace

class QvmError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};  // NTODO is this the way?

struct QvmHeader {
    uint32_t instructionCount;
    uint32_t codeOffset;
    uint32_t codeLength;
    uint32_t dataOffset;
    uint32_t dataLength;
    uint32_t litLength;
    uint32_t bssLength;

    static constexpr size_t kHeaderSize =
        32;  // NTODO: static_assert sizeof struct?
    static constexpr uint32_t kMagic = 0x44147212;

    QvmHeader(const uint8_t* buf, size_t len) {
        if (buf == nullptr || len < kHeaderSize || GetUint32(&buf) != kMagic)
            throw QvmError("Invalid qvm header");
        instructionCount = GetUint32(&buf);
        codeOffset = GetUint32(&buf);
        codeLength = GetUint32(&buf);
        dataOffset = GetUint32(&buf);
        dataLength = GetUint32(&buf);
        litLength = GetUint32(&buf);
        bssLength = GetUint32(&buf);
    }
};

enum Opcode {
    kOpUndef,
    kOpIgnore,
    kOpBreak,
    kOpEnter,
    kOpLeave,
    kOpCall,
    kOpPush,
    kOpPop,
    kOpConst,
    kOpLocal,
    kOpJump,
    kOpEq,
    kOpNE,
    kOpLTI,
    kOpLEI,
    kOpGTI,
    kOpGEI,
    kOpLTU,
    kOpLEU,
    kOpGTU,
    kOpGEU,
    kOpEqF,
    kOpNEF,
    kOpLTF,
    kOpLEF,
    kOpGTF,
    kOpGEF,
    kOpLoad1,
    kOpLoad2,
    kOpLoad4,
    kOpStore1,
    kOpStore2,
    kOpStore4,
    kOpArg,
    kOpBlockCopy,
    kOpSex8,
    kOpSex16,
    kOpNegI,
    kOpAdd,
    kOpSub,
    kOpDivI,
    kOpDivU,
    kOpModI,
    kOpModU,
    kOpMulI,
    kOpMulU,
    kOpBAnd,
    kOpBOr,
    kOpBXor,
    kOpBCom,
    kOpLsh,
    kOpRshI,
    kOpRshU,
    kOpNegF,
    kOpAddF,
    kOpSubF,
    kOpDivF,
    kOpMulF,
    kOpCVIF,
    kOpCVFI
};

// NTODO: this can represent invalid instruction
struct Instruction {
    Opcode opcode;
    uint32_t arg;
};
using Syscall = int32_t(int32_t* args);
class Interpreter {
    vector<uint8_t> data_;
    uint32_t programStack_;
    vector<Instruction> instructions_;
    uint32_t programCounter_;
    Syscall syscall;
    vector<int32_t> opStack_;

   public:
    Interpreter(const uint8_t* buf, size_t len) {
        auto header = QvmHeader(buf, len);
        assert(header.dataLength % 4 == 0);

        instructions_.reserve(header.instructionCount);
        const uint8_t* code = buf + header.codeOffset;
        const uint8_t* code_end = code + header.codeLength;
        while (code != code_end) {
            auto opcode = static_cast<Opcode>(GetUint8(&code));
            uint32_t arg = 0;
            // NTODO: find linter/formatter rule to fix this if cond breaking
            if (opcode == kOpEnter || opcode == kOpLeave ||
                opcode == kOpConst || opcode == kOpLocal ||
                (kOpEq <= opcode && opcode <= kOpGEF)) {
                arg = GetUint32(&code);
            } else if (opcode == kOpArg) {
                arg = GetUint8(&code);
            }
            instructions_.emplace_back(opcode, arg);
        }

        // NTODO: NOTE: qvm reserves space for stack in bss, it begins in
        // dataLength + litLength + bssLength - 64k
        const uint8_t* qvm_data = buf + header.dataOffset;
        if constexpr (std::endian::native == std::endian::little) {
            data_.assign(
                qvm_data, qvm_data + header.dataLength + header.litLength
            );
        } else {
            for (size_t i = 0; i < header.dataLength; i += 4) {
                data_.push_back(GetUint32(&qvm_data));
            }
            data_.insert(data_.end(), qvm_data, qvm_data + header.litLength);
        }
        data_.insert(data_.end(), header.bssLength, 0);
    }

    // NTODO: Think about the API/implementation? Can/should it be safe to:
    // 1) Run while running? (eg. proxy hooked vm syscall calling run again)
    // 2) Run arbitrary function at arbitrary point?
    int32_t run(uint32_t fun, std::initializer_list<int32_t> /*args*/) {
        // NTODO: target validation?
        programCounter_ = fun;
        while (true) {
            const Instruction& instruction = instructions_[programCounter_++];
            printf("instruction %d %d\n", instruction.opcode, instruction.arg);
            switch (instruction.opcode) {
                case kOpUndef:
                case kOpIgnore:
                case kOpBreak:  // NTODO: dispatch signal maybe?
                case kOpEnter:  // NTODO: implement properly
                    break;

                case kOpLeave:
                    if (true /* NTODO detect outermost frame*/) {
                        return opStack_.back();
                    }
                    break;

                case kOpConst:
                    opStack_.push_back(instruction.arg);
                    break;

                case kOpJump:
                    // NTODO: target validation?
                    programCounter_ = pop<uint32_t>();
                    break;

                case kOpEq:
                    branchIf<uint32_t>(std::equal_to(), instruction.arg);
                    break;

                case kOpNE:
                    branchIf<uint32_t>(std::not_equal_to(), instruction.arg);
                    break;

                case kOpLTI:
                    branchIf<int32_t>(std::less(), instruction.arg);
                    break;

                case kOpLEI:
                    branchIf<int32_t>(std::less_equal(), instruction.arg);
                    break;

                case kOpGTI:
                    branchIf<int32_t>(std::greater(), instruction.arg);
                    break;

                case kOpGEI:
                    branchIf<int32_t>(std::greater_equal(), instruction.arg);
                    break;

                case kOpLTU:
                    branchIf<uint32_t>(std::less(), instruction.arg);
                    break;

                case kOpLEU:
                    branchIf<uint32_t>(std::less_equal(), instruction.arg);
                    break;

                case kOpGTU:
                    branchIf<uint32_t>(std::greater(), instruction.arg);
                    break;

                case kOpGEU:
                    branchIf<uint32_t>(std::greater_equal(), instruction.arg);
                    break;

                case kOpEqF:
                    branchIf<float32_t>(std::equal_to(), instruction.arg);
                    break;

                case kOpNEF:
                    branchIf<float32_t>(std::not_equal_to<>(), instruction.arg);
                    break;

                case kOpLTF:
                    branchIf<float32_t>(std::less(), instruction.arg);
                    break;

                case kOpLEF:
                    branchIf<float32_t>(std::less_equal(), instruction.arg);
                    break;

                case kOpGTF:
                    branchIf<float32_t>(std::greater(), instruction.arg);
                    break;

                case kOpGEF:
                    branchIf<float32_t>(std::greater_equal(), instruction.arg);
                    break;

                case kOpAdd:
                    binaryOp<uint32_t>(std::plus());
                    break;

                case kOpSub:
                    binaryOp<uint32_t>(std::minus());
                    break;

                case kOpDivI:
                    binaryOp<int32_t>(std::divides());
                    break;

                case kOpDivU:
                    binaryOp<uint32_t>(std::divides());
                    break;

                case kOpModI:
                    binaryOp<int32_t>(std::modulus());
                    break;

                case kOpModU:
                    binaryOp<uint32_t>(std::modulus());
                    break;

                case kOpMulI:
                    binaryOp<int32_t>(std::multiplies());
                    break;

                case kOpMulU:
                    binaryOp<uint32_t>(std::multiplies());
                    break;

                case kOpBAnd:
                    binaryOp<uint32_t>(std::bit_and());
                    break;

                case kOpBOr:
                    binaryOp<uint32_t>(std::bit_or());
                    break;

                case kOpBXor:
                    binaryOp<uint32_t>(std::bit_xor());
                    break;

                    // case kOpBCom:
                    //   unaryOp<uint32_t>(std::bit_not());
                    //   break;

                case kOpLsh:
                    binaryOp<uint32_t>([](auto lhs, auto rhs) {
                        return lhs << rhs;
                    });
                    break;

                case kOpRshI:
                    binaryOp<int32_t>([](auto lhs, auto rhs) {
                        return lhs >> rhs;
                    });
                    break;

                case kOpRshU:
                    binaryOp<uint32_t>([](auto lhs, auto rhs) {
                        return lhs >> rhs;
                    });
                    break;

                    // case kOpNegF:
                    //   unaryOp<float32_t>(std::negate());
                    //   break;

                case kOpAddF:
                    binaryOp<float32_t>(std::plus());
                    break;

                case kOpSubF:
                    binaryOp<float32_t>(std::minus());
                    break;

                case kOpDivF:
                    binaryOp<float32_t>(std::divides());
                    break;

                case kOpMulF:
                    binaryOp<float32_t>(std::multiplies());
                    break;

                case kOpCVIF:
                    opStack_.back() = static_cast<float32_t>(opStack_.back());
                    break;

                case kOpCVFI:
                    opStack_.back() = static_cast<int32_t>(
                        std::bit_cast<float32_t>(opStack_.back())
                    );
                    break;

                default:
                    // NTODO: move validation to init time and make this
                    // unreachable!() once all opcodes are supported?
                    throw std::runtime_error("unimplemented?");
            }
        }
    };

   private:
    template <typename T>
    T pop() {
        uint32_t top_of_stack = opStack_.back();
        opStack_.pop_back();
        return std::bit_cast<T>(top_of_stack);
    }

    template <typename T>
    void binaryOp(auto f) {
        auto rhs = pop<T>();
        auto lhs = pop<T>();
        opStack_.push_back(f(lhs, rhs));
    }

    template <typename T>
    void branchIf(auto f, uint32_t target) {
        auto rhs = pop<T>();
        auto lhs = pop<T>();
        if (f(lhs, rhs)) {
            programCounter_ = target;  // NTODO: target validation?
        }
    }
};

int main(int /*argc*/, const char* /*argv*/[]) {
    uint8_t my_cool_qvm[] = {
        0x12, 0x72, 0x14, 0x44,  // magic
        0x05, 0x00, 0x00, 0x00,  // 3 instructions
        0x20, 0x00, 0x00, 0x00,  // code offset
        0x15, 0x00, 0x00, 0x00,  // code size
        0x00, 0x00, 0x00, 0x00,  // data offset
        0x00, 0x00, 0x00, 0x00,  // data size
        0x00, 0x00, 0x00, 0x00,  // lit size
        0x00, 0x00, 0x01, 0x00,  // bss size

        0x03, 0x08, 0x00, 0x00, 0x00,  // ENTER 8
        0x08, 0x7b, 0x00, 0x00, 0x00,  // CONST 123
        0x08, 0x7b, 0x00, 0x00, 0x00,  // CONST 123
        0x26,                          // ADD
        0x04, 0x08, 0x00, 0x00, 0x00,  // LEAVE 8
    };
    Interpreter interpreter(my_cool_qvm, sizeof(my_cool_qvm));
    printf("%d\n", interpreter.run(0, {}));
    return 0;
}
