inherit .DHCPOption;

constant option_type = 8;

int elapsed_time;

protected variant void create(int since) {
  if(!since) elapsed_time = 0;
  else {
    elapsed_time = (time() - since) * 100; // hundredths of a second
    if(elapsed_time > 0xffff) elapsed_time = 0xffff;
  }
}

void encode_body(Stdio.Buffer buf) {
  buf->add_int(elapsed_time, 2);
}

void decode_body(Stdio.Buffer buf) {
  elapsed_time = buf->read_int(2);
}
