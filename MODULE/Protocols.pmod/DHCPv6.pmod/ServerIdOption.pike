inherit .DHCPOption;

constant option_type = 2;

.DUID duid;

protected variant void create(.DUID _duid) {
  duid = _duid;
}

void encode_body(Stdio.Buffer buf) {
  buf->add(duid->encode());
}

void decode_body(Stdio.Buffer buf) {
  duid = .DUID(buf->read());
}
