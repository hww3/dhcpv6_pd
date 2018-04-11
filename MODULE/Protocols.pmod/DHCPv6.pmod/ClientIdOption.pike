inherit .DHCPOption;

constant option_type = 1;

.DUID duid;

mixed _encode() {
  return ([ "duid": duid ]);
}

void _decode(mixed x) {
  duid = x->duid;
}

protected variant void create(.DUID _duid) {
  duid = _duid;
}

void encode_body(Stdio.Buffer buf) {
  buf->add(duid->encode());
}

void decode_body(Stdio.Buffer buf) {
  duid = .DUID(buf->read());
}
