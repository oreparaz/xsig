package lowlevel

// DeviceContext provides runtime-supplied device information to the evaluator.
type DeviceContext struct {
	DeviceID []byte // exactly 32 bytes, or nil if not set
}
