inherit .DHCPOption;

constant option_type = 6;
array(array(int)) options;

protected void create(array(array(int)) _options) {
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

  foreach(options;; array option) {
     if(sizeof(option) != 2) throw(Error.Generic("OptionRequestOptions must be a multiple of 2.\n"));
     buf->add_int(option[0], 2);
     buf->add_int(option[1], 2);
  }
}

void decode_body(Stdio.Buffer buf) {
  options = ({});
  while(sizeof(buf)) {
    array(int) option = allocate(2);
    option[0] = buf->read_int(2);
    option[1] = buf->read_int(2);
    options+=({ option });
  }
}
