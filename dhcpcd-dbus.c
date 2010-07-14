/*
 * dhcpcd-dbus
 * Copyright 2009 Roy Marples <roy@marples.name>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <dbus/dbus.h>

#include "config.h"
#include "eloop.h"
#include "dbus-dict.h"
#include "dhcpcd-dbus.h"
#include "dhcpcd.h"

#define S_EINVAL	DHCPCD_SERVICE ".InvalidArgument"
#define S_ARGS		"Not enough arguments"

static DBusConnection *connection;

static const char dhcpcd_introspection_xml[] =
    "    <method name=\"GetVersion\">\n"
    "      <arg name=\"version\" direction=\"out\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"GetInterfaces\">\n"
    "      <arg name=\"interfaces\" direction=\"out\" type=\"a{sa{sv}}\"/>\n"
    "    </method>\n"
    "    <method name=\"GetStatus\">\n"
    "      <arg name=\"Status\" direction=\"out\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"Rebind\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"Release\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <method name=\"Stop\">\n"
    "      <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
    "    </method>\n"
    "    <signal name=\"Event\">\n"
    "      <arg name=\"configuration\" type=\"usa{sv}\"/>\n"
    "    </signal>\n"
    "    <signal name=\"StatusChanged\">\n"
    "      <arg name=\"status\" type=\"us\"/>\n"
    "    </signal>\n";

static const struct o_dbus const dhos[] = {
	{ "ip_address=", DBUS_TYPE_UINT32, 0, "IPAddress" },
	{ "server_name=", DBUS_TYPE_STRING, 0, "ServerName"},
	{ "subnet_mask=", DBUS_TYPE_UINT32, 0, "SubnetMask" },
	{ "subnet_cidr=", DBUS_TYPE_BYTE, 0, "SubnetCIDR" },
	{ "network_number=", DBUS_TYPE_UINT32, 0, "NetworkNumber" },
	{ "classless_static_routes=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "ClasslessStaticRoutes" },
	{ "ms_classless_static_routes=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "MSClasslessStaticRoutes" },
	{ "static_routes=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "StaticRoutes"} ,
	{ "routers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "Routers" },
	{ "time_offset=", DBUS_TYPE_UINT32, 0, "TimeOffset" },
	{ "time_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "TimeServers" },
	{ "ien116_name_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "IEN116NameServers" },
	{ "domain_name_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "DomainNameServers" },
	{ "log_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "LogServers" },
	{ "cookie_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "CookieServers" },
	{ "lpr_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "LPRServers" },
	{ "impress_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "ImpressServers" },
	{ "resource_location_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "ResourceLocationServers" },
	{ "host_name=", DBUS_TYPE_STRING, 0, "Hostname" },
	{ "boot_size=", DBUS_TYPE_UINT16, 0, "BootSize" },
	{ "merit_dump=", DBUS_TYPE_STRING, 0, "MeritDump" },
	{ "domain_name=", DBUS_TYPE_STRING, 0, "DomainName" },
	{ "swap_server=", DBUS_TYPE_UINT32, 0, "SwapServer" },
	{ "root_path=", DBUS_TYPE_STRING, 0, "RootPath" },
	{ "extensions_path=", DBUS_TYPE_STRING, 0, "ExtensionsPath" },
	{ "ip_forwarding=", DBUS_TYPE_BOOLEAN, 0, "IPForwarding" },
	{ "non_local_source_routing=", DBUS_TYPE_BOOLEAN, 0,
	  "NonLocalSourceRouting" },
	{ "policy_filter=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "PolicyFilter" },
	{ "max_dgram_reassembly=", DBUS_TYPE_INT16, 0,
	  "MaxDatagramReassembly" },
	{ "default_ip_ttl=", DBUS_TYPE_UINT16, 0, "DefaultIPTTL" },
	{ "path_mtu_aging_timeout=", DBUS_TYPE_UINT32, 0,
	  "PathMTUAgingTimeout" },
	{ "path_mtu_plateau_table=" ,DBUS_TYPE_ARRAY, DBUS_TYPE_UINT16,
	  "PolicyFilter"} ,
	{ "interface_mtu=", DBUS_TYPE_UINT16, 0, "InterfaceMTU" },
	{ "all_subnets_local=", DBUS_TYPE_BOOLEAN, 0, "AllSubnetsLocal" },
	{ "broadcast_address=", DBUS_TYPE_UINT32, 0, "BroadcastAddress" },
	{ "perform_mask_discovery=", DBUS_TYPE_BOOLEAN, 0,
	  "PerformMaskDiscovery" },
	{ "mask_supplier=", DBUS_TYPE_BOOLEAN, 0, "MaskSupplier" },
	{ "router_discovery=", DBUS_TYPE_BOOLEAN, 0, "RouterDiscovery" },
	{ "router_solicitiation_address=", DBUS_TYPE_UINT32, 0,
	  "RouterSolicationAddress" },
	{ "trailer_encapsulation=", DBUS_TYPE_BOOLEAN, 0,
	  "TrailerEncapsulation" },
	{ "arp_cache_timeout=", DBUS_TYPE_UINT32, 0, "ARPCacheTimeout" },
	{ "ieee802_3_encapsulation=", DBUS_TYPE_UINT16, 0,
	  "IEEE8023Encapsulation" },
	{ "default_tcp_ttl=", DBUS_TYPE_BYTE, 0, "DefaultTCPTTL" },
	{ "tcp_keepalive_interval=", DBUS_TYPE_UINT32, 0,
	  "TCPKeepAliveInterval" },
	{ "tcp_keepalive_garbage=", DBUS_TYPE_BOOLEAN, 0,
	  "TCPKeepAliveGarbage" },
	{ "nis_domain=", DBUS_TYPE_STRING, 0, "NISDomain" },
	{ "nis_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NISServers" },
	{ "ntp_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NTPServers" },
	{ "vendor_encapsulated_optons=", DBUS_TYPE_STRING, 0,
	  "VendorEncapsulatedOptions" },
	{ "netbios_name_servers=" ,DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "NetBIOSNameServers" },
	{ "netbios_dd_server=", DBUS_TYPE_UINT32, 0, "NetBIOSDDServer" },
	{ "netbios_node_type=", DBUS_TYPE_BYTE, 0, "NetBIOSNodeType" },
	{ "netbios_scope=", DBUS_TYPE_STRING, 0, "NetBIOSScope" },
	{ "font_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "FontServers" },
	{ "x_display_manager=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "XDisplayManager" },
	{ "dhcp_requested_address=", DBUS_TYPE_UINT32, 0,
	  "DHCPRequestedAddress" },
	{ "dhcp_lease_time=", DBUS_TYPE_UINT32, 0, "DHCPLeaseTime" },
	{ "dhcp_option_overload=", DBUS_TYPE_BOOLEAN, 0,
	  "DHCPOptionOverload" },
	{ "dhcp_message_type=", DBUS_TYPE_BYTE, 0, "DHCPMessageType" },
	{ "dhcp_server_identifier=", DBUS_TYPE_UINT32, 0,
	  "DHCPServerIdentifier" },
	{ "dhcp_message=", DBUS_TYPE_STRING, 0, "DHCPMessage" },
	{ "dhcp_max_message_size=", DBUS_TYPE_UINT16, 0,
	  "DHCPMaxMessageSize" },
	{ "dhcp_renewal_time=", DBUS_TYPE_UINT32, 0, "DHCPRenewalTime" },
	{ "dhcp_rebinding_time=", DBUS_TYPE_UINT32, 0, "DHCPRebindingTime" },
	{ "nisplus_domain=", DBUS_TYPE_STRING, 0, "NISPlusDomain" },
	{ "nisplus_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "NISPlusServers" },
	{ "tftp_server_name=", DBUS_TYPE_STRING, 0, "TFTPServerName" },
	{ "bootfile_name=", DBUS_TYPE_STRING, 0, "BootFileName" },
	{ "mobile_ip_home_agent=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "MobileIPHomeAgent" },
	{ "smtp_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "SMTPServer" },
	{ "pop_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "POPServer" },
	{ "nntp_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NNTPServer" },
	{ "www_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "WWWServer" },
	{ "finger_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "FingerServer" },
	{ "irc_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "IRCServer" },
	{ "streettalk_server=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "StreetTalkServer" },
	{ "streettalk_directory_assistance_server=", DBUS_TYPE_ARRAY,
	  DBUS_TYPE_UINT32, "StreetTalkDirectoryAssistanceServer" },
	{ "user_class=", DBUS_TYPE_STRING, 0, "UserClass" },
	{ "new_fqdn_name=", DBUS_TYPE_STRING, 0, "FQDNName" },
	{ "nds_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "NDSServers" },
	{ "nds_tree_name=", DBUS_TYPE_STRING, 0, "NDSTreeName" },
	{ "nds_context=", DBUS_TYPE_STRING, 0, "NDSContext" },
	{ "bcms_controller_names=", DBUS_TYPE_STRING, 0,
	  "BCMSControllerNames" },
	{ "client_last_transaction_time=", DBUS_TYPE_UINT32, 0,
	  "ClientLastTransactionTime" },
	{ "associated_ip=", DBUS_TYPE_UINT32, 0, "AssociatedIP" },
	{ "uap_servers=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, "UAPServers" },
	{ "netinfo_server_address=", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
	  "NetinfoServerAddress" },
	{ "netinfo_server_tag=", DBUS_TYPE_STRING, 0, "NetinfoServerTag" },
	{ "default_url=", DBUS_TYPE_STRING, 0, "DefaultURL" },
	{ "subnet_selection=", DBUS_TYPE_UINT32, 0, "SubnetSelection" },
	{ "domain_search=", DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
	  "DomainSearch" },
	{ NULL, 0, 0, NULL }
};

static int
append_config(DBusMessageIter *iter,
    const char *prefix, char **env, ssize_t elen)
{
	char **eenv, *p;
	const struct o_dbus *dhop;
	size_t l, lp;
	int retval;

	retval = 0;
	lp = strlen(prefix);
	for (eenv = env + elen; env < eenv; env++) {
		p = env[0];
		for (dhop = dhos; dhop->var; dhop++) {
			l = strlen(dhop->var);
			if (strncmp(p, dhop->var, l) == 0) {
				retval = dict_append_config_item(iter,
				    dhop, p + l);
				break;
			}
			if (strncmp(p, prefix, lp) == 0 &&
			    strncmp(p + lp, dhop->var, l) == 0)
			{
				retval = dict_append_config_item(iter,
				    dhop, p + l + lp);
				break;
			}
		}
		if (retval == -1)
			break;
	}
	return retval;
}

DBusHandlerResult _printf(4, 5)
	return_dbus_error(DBusConnection *con, DBusMessage *msg,
	    const char *name, const char *fmt, ...)
{
	char buffer[1024];
	DBusMessage *reply;
	va_list args;

	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	reply = dbus_message_new_error(msg, name, buffer);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

const char *dhcpcd_status = NULL;	/* XXX */

static DBusHandlerResult
return_status(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply,
	    DBUS_TYPE_STRING, &dhcpcd_status,
	    DBUS_TYPE_INVALID);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

void
dhcpcd_dbus_signal_status(const char *status)
{
	DBusMessage *msg;
	DBusMessageIter args;
	int pid = getpid();

	syslog(LOG_INFO, "status changed to %s", status);

	msg = dbus_message_new_signal(DHCPCD_PATH, DHCPCD_SERVICE,
	    "StatusChanged");
	if (msg == NULL) {
		syslog(LOG_ERR, "failed to make a status changed message");
		return;
	}
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &pid);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &status);
	if (!dbus_connection_send(connection, msg, NULL))
		syslog(LOG_ERR, "failed to send status to dbus");
	dbus_message_unref(msg);
}

void
dhcpcd_dbus_configure(const struct interface *ifp, const char *reason)
{
	const struct if_options *ifo = ifp->state->options;
	DBusMessage* msg;
	DBusMessageIter args, dict;
	int pid = getpid();
	char **env;
	ssize_t e, elen;
	int retval;

	syslog(LOG_INFO, "event %s on interface %s", reason, ifp->name);

	msg = dbus_message_new_signal(DHCPCD_PATH, DHCPCD_SERVICE, "Event");
	if (msg == NULL) {
		syslog(LOG_ERR, "failed to make a configure message");
		return;
	}
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &pid);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &reason);
	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY,
	    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_VARIANT_AS_STRING
	    DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
	    &dict);
	if (ifp->state->new != NULL) {
		e = configure_env(NULL, NULL, ifp->state->new, ifo);
		if (e > 0) {
			env = xzalloc(sizeof(char *) * (e + 1));
			elen = configure_env(env, "new", ifp->state->new, ifo);
		}
		retval = append_config(&dict, "new_", env, elen);
	} else if (ifp->state->old != NULL) {
		e = configure_env(NULL, NULL, ifp->state->old, ifo);
		if (e > 0) {
			env = xzalloc(sizeof(char *) * (elen + e + 1));
			elen = configure_env(env, "old", ifp->state->old, ifo);
		}
		retval = append_config(&dict, "old_", env, elen);
	} else
		retval = 0;
	/* XXX reclaim env */
	dbus_message_iter_close_container(&args, &dict);
	if (retval == 0) {
		if (!dbus_connection_send(connection, msg, NULL))
			syslog(LOG_ERR, "failed to send dhcp to dbus");
	} else
		syslog(LOG_ERR, "failed to construct dbus message");
	dbus_message_unref(msg);
}

static const char introspection_header_xml[] =
    "<!DOCTYPE node PUBLIC \"-//freedesktop//"
    "DTD D-BUS Object Introspection 1.0//EN\"\n"
    "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
    "<node name=\"" DHCPCD_PATH "\">\n"
    "  <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
    "    <method name=\"Introspect\">\n"
    "      <arg name=\"data\" direction=\"out\" type=\"s\"/>\n"
    "    </method>\n"
    "  </interface>\n"
    "  <interface name=\"" DHCPCD_SERVICE "\">\n";

static const char introspection_footer_xml[] =
    "  </interface>\n"
    "</node>\n";

static DBusHandlerResult
introspect(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	char *xml;
	size_t len;

	len = sizeof(introspection_header_xml) - 1
	    + sizeof(dhcpcd_introspection_xml) - 1
	    + sizeof(introspection_footer_xml) - 1
	    + 1; /* terminal \0 */
	xml = malloc(len);
	if (xml == NULL)
		return DBUS_HANDLER_RESULT_HANDLED;
	snprintf(xml, len, "%s%s%s",
	    introspection_header_xml,
	    dhcpcd_introspection_xml,
	    introspection_footer_xml);
	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply,
	    DBUS_TYPE_STRING, &xml,
	    DBUS_TYPE_INVALID);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	free(xml);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
version(DBusConnection *con, DBusMessage *msg, const char *ver)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply,
	    DBUS_TYPE_STRING, &ver,
	    DBUS_TYPE_INVALID);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
dhcpcd_get_interfaces(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter _ifaces, _iface, entry, dict;
	struct interface *ifp;
	char **env;
	ssize_t e, elen;
	int retval;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &_ifaces);

	dbus_message_iter_open_container(&_ifaces, DBUS_TYPE_ARRAY,
	    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_ARRAY_AS_STRING
	    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
	    DBUS_TYPE_STRING_AS_STRING
	    DBUS_TYPE_VARIANT_AS_STRING
	    DBUS_DICT_ENTRY_END_CHAR_AS_STRING
	    DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
	    &_iface);

	for (ifp = ifaces; ifp != NULL; ifp = ifp->next) {
		const struct if_options *ifo = ifp->state->options;

		dbus_message_iter_open_container(&_iface,
		    DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry,
		    DBUS_TYPE_STRING, &ifp->name);
		dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
		    DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		    DBUS_TYPE_STRING_AS_STRING
		    DBUS_TYPE_VARIANT_AS_STRING
		    DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
		    &dict);
		e = configure_env(NULL, NULL, ifp->state->new, ifo);
		if (e > 0) {
			env = xzalloc(sizeof(char *) * (e + 1));
			elen = configure_env(env, "new", ifp->state->new, ifo);
		}
		retval = append_config(&dict, "new_", env, elen);
		/* XXX reclaim env */
		dbus_message_iter_close_container(&entry, &dict);
		dbus_message_iter_close_container(&_iface, &entry);
	}

	dbus_message_iter_close_container(&_ifaces, &_iface);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
dbus_ack(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
msg_handler(DBusConnection *con, DBusMessage *msg, _unused void *data)
{
#define	IsMethod(msg, method) \
	dbus_message_is_method_call(msg, DHCPCD_SERVICE, method)
	if (dbus_message_is_method_call(msg, DBUS_INTERFACE_INTROSPECTABLE,
                                        "Introspect")) {
		return introspect(con, msg);
	} else if (IsMethod(msg, "GetVersion")) {
		return version(con, msg, VERSION);
	} else if (IsMethod(msg, "GetInterfaces")) {
		return dhcpcd_get_interfaces(con, msg);
	} else if (IsMethod(msg, "GetStatus")) {
		return return_status(con, msg);
	} else if (IsMethod(msg, "Rebind")) {
		start_interface(ifaces);
		return dbus_ack(con, msg);
	} else if (IsMethod(msg, "Release")) {
		send_release(ifaces);
		stop_interface(ifaces);
		return dbus_ack(con, msg);
	} else if (IsMethod(msg, "Stop")) {
		stop_interface(ifaces);
		(void) dbus_ack(con, msg);
		exit(EXIT_FAILURE);
	} else if (dbus_message_is_signal(msg, DBUS_INTERFACE_LOCAL,
					  "Disconnected")) {
		stop_interface(ifaces);
		exit(EXIT_FAILURE);
	}
	return return_dbus_error(con, msg, S_EINVAL, S_ARGS);
#undef IsMethod
}

static void
dbus_event(int revents, void *watch)
{
	int flags;

	flags = 0;
	if (revents & POLLIN)
		flags |= DBUS_WATCH_READABLE;
	if (revents & POLLOUT)
		flags |= DBUS_WATCH_WRITABLE;
	if (revents & POLLHUP)
		flags |= DBUS_WATCH_HANGUP;
	if (revents & POLLERR)
		flags |= DBUS_WATCH_ERROR;
	if (flags != 0)
		dbus_watch_handle((DBusWatch *)watch, flags);

	if (connection != NULL) {
		dbus_connection_ref(connection);
		while (dbus_connection_dispatch(connection) ==
		    DBUS_DISPATCH_DATA_REMAINS)
			;
		dbus_connection_unref(connection);
	}
}

static dbus_bool_t
add_watch(DBusWatch *watch, _unused void *data)
{
	int fd, flags, eflags;

	fd = dbus_watch_get_unix_fd(watch);
	flags = dbus_watch_get_flags(watch);
	eflags = POLLHUP | POLLERR;
	if (flags & DBUS_WATCH_READABLE)
		eflags |= POLLIN;
	if (flags & DBUS_WATCH_WRITABLE)
		eflags |= POLLOUT;
	if (add_event_flags(fd, eflags, dbus_event, watch) == 0)
		return TRUE;
	return FALSE;
}

static void
remove_watch(DBusWatch *watch, _unused void *data)
{
	int fd;

	fd = dbus_watch_get_unix_fd(watch);
	delete_event(fd);
}

void
dhcpcd_dbus_close(void)
{
	if (connection) {
		dbus_connection_unref(connection);
		connection = NULL;
	}
}

int
dhcpcd_dbus_init(void)
{
	DBusObjectPathVTable vt = {
		NULL, &msg_handler, NULL, NULL, NULL, NULL
	};
	DBusError err;
	int ret;

	dbus_error_init(&err);
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (connection == NULL) {
		if (dbus_error_is_set(&err))
			syslog(LOG_ERR, "%s", err.message);
		else
			syslog(LOG_ERR, "failed to get a dbus connection");
		return -1;
	}
	atexit(dhcpcd_dbus_close);

	if (!dbus_connection_set_watch_functions(connection,
		add_watch, remove_watch, NULL, NULL, NULL))
	{
		syslog(LOG_ERR, "dbus: failed to set watch functions");
		return -1;
	}
	if (!dbus_connection_register_object_path(connection,
		DHCPCD_PATH, &vt, NULL))
	{
		syslog(LOG_ERR, "dbus: failed to register object path");
		return -1;
	}
	return 0;
}

int
configure(struct interface *ifp)
{
	if (ifp->state->new != NULL) {
		/* push state over d-bus */
		dhcpcd_dbus_configure(ifp, ifp->state->reason);

		if (write_lease(ifp, ifp->state->new) == -1)
			syslog(LOG_ERR, "write_lease: %m");
	}
	return 0;
}

int
run_script(const struct interface *ifp)
{
	return 0;
}
