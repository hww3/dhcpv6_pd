inherit .DHCPOption;

constant option_type = 13;

int status_code;
string status_message;

mixed _encode() {
  return ([ "status_code": status_code, "status_message": status_message ]);
}

void _decode(mixed x) {
  status_code = x->status_code;
  status_message = x->status_message;
}

protected variant void create(int code, string message) {
   status_code = code;
   status_message = message;
}

void encode_body(Stdio.Buffer buf) {
  buf->add_int(status_code, 2);
  buf->add(string_to_utf8(status_message));
}

void decode_body(Stdio.Buffer buf) {
  status_code = buf->read_int(2);
  status_message = utf8_to_string(buf->read());
}
