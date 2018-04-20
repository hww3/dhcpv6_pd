import Protocols.DHCPv6;

object config;

protected void create(object _config) {
  config = _config;
}

string get_identifier();
void prefix_acquired(IA_PDOption allocation, int has_changed, IA_PDOption old_allocation);
void prefix_abandoned(IA_PDOption allocation);

