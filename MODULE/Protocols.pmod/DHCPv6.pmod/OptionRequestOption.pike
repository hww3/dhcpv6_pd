inherit .DHCPOption;

constant option_type = 6;
array(int) options;

protected void create(array(int) _options) {
  options = _options;
}

mixed _encode() {
  return (["options": options]);
}

void _decode(mixed x) {
  options = x->options;
}

protected variant void create() {
  options = ({});
}

void encode_body(Stdio.Buffer buf) {

  foreach(options;; int option) {
     buf->add_int(option, 2);
  }
}

void decode_body(Stdio.Buffer buf) {
  options = ({});
  while(sizeof(buf)) {
    int option = buf->read_int(2);
    options+=({ option });
  }
}
