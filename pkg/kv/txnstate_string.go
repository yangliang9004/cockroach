// Code generated by "stringer -type=txnState"; DO NOT EDIT.

package kv

import "strconv"

const _txnState_name = "txnPendingtxnErrortxnFinalized"

var _txnState_index = [...]uint8{0, 10, 18, 30}

func (i txnState) String() string {
	if i < 0 || i >= txnState(len(_txnState_index)-1) {
		return "txnState(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _txnState_name[_txnState_index[i]:_txnState_index[i+1]]
}
