
constant DHCP_CLIENT_PORT = 546; 
constant DHCP_SERVER_PORT = 547;

constant DHCP_BROADCAST_ADDRESS = "FF02::1:2";

string v6if = "net0";
string identifier;

Stdio.UDP dhcp;
Protocols.DHCPv6.DUID duid;

int main(int argc, array argv) {
  identifier = Standards.JSON.decode(Process.popen("sysinfo"))->UUID;
  werror("Identifier: %O\n", identifier);
  dhcp = Stdio.UDP();
  dhcp->bind(DHCP_CLIENT_PORT, "2001:558:6003:2a:79b0:ea90:48d2:3ad7");
  dhcp->enable_broadcast();
  dhcp->set_nonblocking();
  dhcp->set_read_callback(got_packet);
call_out(send_solicit, 5);
  return -1;
}

void got_packet(mapping data, mixed ... args) {
  werror("got_packet(%O, %O)\n", data, args);
  object x = Protocols.DHCPv6.decode_message(data->data);
  werror("x: %O options: %O\n", x, x->options[0]);
  werror("o: %O\n", mkmapping(indices(x->options[0]), values(x->options[0])));
}

void send(Protocols.DHCPv6.DHCPMessage message, string dest, int port) {
  string m = message->encode();
  werror("sending message: %O -> %O on port %d\n", message, m, port);
  dhcp->send(dest, port, m);
}

void send_broadcast(Protocols.DHCPv6.DHCPMessage message) {
  send(message, DHCP_BROADCAST_ADDRESS, DHCP_SERVER_PORT);
}

void send_solicit() {
  object p = Protocols.DHCPv6.SolicitMessage(Protocols.DHCPv6.generate_transaction_id());
  object id = Protocols.DHCPv6.ClientIdOption(Protocols.DHCPv6.DUID(0, identifier));
  object pd_opt = Protocols.DHCPv6.IA_PDOption(3600*24, 3600*36, 64, 0);
  object ia_ident = Protocols.DHCPv6.IAID(Crypto.MD5.hash(v6if)[0..3]);

  p->options += ({id});
  p->options += ({Protocols.DHCPv6.OptionRequestOption()});
  p->options += ({Protocols.DHCPv6.ElapsedTimeOption(0)});
  p->options += ({Protocols.DHCPv6.IAPD(ia_ident, 3600*24, 3600*36, ({pd_opt}))
});
  send_broadcast(p);
}
