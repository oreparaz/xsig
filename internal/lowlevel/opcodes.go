package lowlevel

// nit: we're not using iota since these values are exported
const OP_ADD = byte(1)
const OP_MUL = byte(2)
const OP_PUSH = byte(3)
const OP_SIGVERIFY = byte(4)
const OP_MULTISIGVERIFY = byte(5)
const OP_AND = byte(6)
const OP_OR  = byte(7)
const OP_NOT = byte(8)
const OP_EQUAL32 = byte(9)
const OP_DEVICEID = byte(10)
