const r4os = @import("r4os");
const std = @import("std");
const network = r4os.network_family.common;
const dns_codec = @import("dns_address_codec");

const service_name = "DNSSVC";
const selftest_arg = "/SELFTEST";
const ping_arg = "/PING";

const dns_port: u16 = 53;
const dns_type_a: u16 = 1;
const dns_type_cname: u16 = 5;
const dns_class_in: u16 = 1;
const dns_timeout_ms: u64 = 3000;
const dns_default_ttl_seconds: u32 = 60;
const dns_negative_ttl_seconds: u32 = 20;
const dns_cache_entries_max: usize = 8;
const dns_query_max: usize = 512;
const dns_name_max: usize = 96;
const dns_error_max: usize = 32;
const dns_source_port_base: u16 = 53000;

const DnsCacheEntry = struct {
    query_id: u64 = 0,
    query_owner: u32 = 0,
    query_owner_generation: u64 = 0,
    query_expires_ns: u64 = 0,
    query_port: u16 = dns_port,
    query_answers: dns_codec.Answer = .{},
    valid: bool = false,
    negative: bool = false,
    name: [256]u8 = .{0} ** 256,
    server: [4]u8 = .{0} ** 4,
    answer: [4]u8 = .{0} ** 4,
    updated_seconds: u64 = 0,
    ttl_seconds: u32 = dns_default_ttl_seconds,
};

const DnsState = struct {
    provider: u64 = 0,
    next_query: u64 = 1,
    typed_clock: ?r4os.time_contract.checked.ClockSample = null,
    queries_tx: u64 = 0,
    resolve_requests: u64 = 0,
    responses_rx: u64 = 0,
    a_records: u64 = 0,
    timeouts: u64 = 0,
    nxdomain: u64 = 0,
    tx_errors: u64 = 0,
    malformed: u64 = 0,
    self_tests: u64 = 0,
    cache_hits: u64 = 0,
    cache_stores: u64 = 0,
    requests: u64 = 0,
    bad_ops: u64 = 0,
    last_id: u16 = 0,
    next_id: u16 = 0x4400,
    last_result: i32 = r4os.abi.dns_result_tx,
    last_server: [4]u8 = .{0} ** 4,
    last_answer: [4]u8 = .{0} ** 4,
    last_name: [dns_name_max]u8 = .{0} ** dns_name_max,
    operation_pending: bool = false,
    pending_name: [dns_name_max]u8 = .{0} ** dns_name_max,
    cache_valid: bool = false,
    cache_name: [dns_name_max]u8 = .{0} ** dns_name_max,
    cache_server: [4]u8 = .{0} ** 4,
    cache_answer: [4]u8 = .{0} ** 4,
    cache_updated_seconds: u64 = 0,
    cache_ttl_seconds: u32 = dns_default_ttl_seconds,
    last_error: [dns_error_max]u8 = .{0} ** dns_error_max,
    cache: [dns_cache_entries_max]DnsCacheEntry = .{DnsCacheEntry{}} ** dns_cache_entries_max,
    cache_next: usize = 0,
};

const App = struct {
    sys: r4os.r4sys.Context,
    net: r4os.r4net.Context,

    fn init(r4_app: *r4os.App) ?App {
        return .{
            .sys = r4_app.system(),
            .net = r4_app.networkLowLevel() orelse return null,
        };
    }
};

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    var app = App.init(r4_app) orelse return r4os.abi.err_no_group;
    if (hasArg(app.sys.argsRaw(), selftest_arg)) return runSelfTest(&app);
    if (hasArg(app.sys.argsRaw(), ping_arg)) return runPing(&app);
    return runService(&app);
}

fn runService(app: *const App) i32 {
    if (!app.sys.hasFn("service_call")) return r4os.abi.service_api_result_invalid;

    var info: r4os.abi.ServiceInfo = .{};
    var handle: u32 = 0;
    var waited: u32 = 0;
    while (waited < 100 and handle == 0) : (waited += 1) {
        const rc = app.sys.serviceEndpointRegister(service_name, 0, &info);
        if (rc == r4os.abi.service_api_result_ok and info.handle != 0) {
            handle = info.handle;
            app.sys.write("DNSSVC endpoint handle=");
            app.sys.printU64(@intCast(handle));
            app.sys.println("");
            break;
        }
        app.sys.sleepTicks(1);
    }
    if (handle == 0) {
        app.sys.println("DNSSVC endpoint registration failed");
        return r4os.abi.service_api_result_no_endpoint;
    }

    var state = DnsState{ .provider = network.provider(app.sys) catch 0 };
    setLastError(&state, "ready");
    var service_loop = r4os.ServiceLoop.init(app.sys, handle, .{});
    while (true) {
        switch (service_loop.wait(null)) {
            .requests => |pending| {
                const rc = service_loop.drain(pending, handleRequest, .{ app, handle, &state });
                if (rc >= 0) continue;
                _ = app.sys.serviceEndpointUnregister(handle);
                return rc;
            },
            .idle, .deadline => {},
            .stop => break,
            .failure => |raw| {
                _ = app.sys.serviceEndpointUnregister(handle);
                return raw;
            },
        }
    }

    service_loop.report(service_name);
    _ = app.sys.serviceEndpointUnregister(handle);
    app.sys.println("DNSSVC stopped cleanly");
    return 0;
}

fn handleRequest(app: *const App, handle: u32, state: *DnsState) i32 {
    var header: r4os.abi.ServiceMessageHeader = .{};
    var payload: [r4os.abi.service_api_max_payload]u8 = undefined;
    const got = app.sys.serviceEndpointRecv(handle, &header, payload[0..]);
    if (got < 0) return got;
    if (got == 0 and header.magic != r4os.abi.service_api_magic) return 0;

    state.requests +%= 1;
    const payload_len: usize = @intCast(got);
    const request = payload[0..payload_len];
    if (header.op >= r4os.abi.network_op_info and header.op <= r4os.abi.network_op_release) return replyNetwork(app, handle, header.request_id, state, header.client_id, header.op, request);
    return switch (header.op) {
        r4os.abi.net_service_op_status => replyTextStatus(app, handle, header.request_id, state),
        r4os.abi.net_service_op_dns_status_result => replyStatusResult(app, handle, header.request_id, state),
        r4os.abi.net_service_op_dns_resolve_a, r4os.abi.net_service_op_dns_resolve_a_server => replyResolveText(app, handle, header.request_id, header.op, request, state),
        r4os.abi.net_service_op_dns_resolve_a_result, r4os.abi.net_service_op_dns_resolve_a_server_result => replyResolveResult(app, handle, header.request_id, header.op, request, state),
        else => {
            state.bad_ops +%= 1;
            return r4os.app_services.replyIfPending(app.sys, handle, header.request_id, r4os.abi.service_api_result_bad_op, "BADOP");
        },
    };
}

fn replyTextStatus(app: *const App, handle: u32, request_id: u32, state: *const DnsState) i32 {
    var buf: [512]u8 = .{0} ** 512;
    var w = Writer{ .out = buf[0..] };
    writeStatusText(&w, app, state);
    return r4os.app_services.replyIfPending(app.sys, handle, request_id, r4os.abi.service_api_result_ok, w.slice());
}

fn replyStatusResult(app: *const App, handle: u32, request_id: u32, state: *DnsState) i32 {
    const status = makeStatusResult(app, state);
    const bytes: [*]const u8 = @ptrCast(&status);
    return r4os.app_services.replyIfPending(app.sys, handle, request_id, r4os.abi.service_api_result_ok, bytes[0..@sizeOf(r4os.abi.NetServiceDnsStatus)]);
}

fn replyResolveText(app: *const App, handle: u32, request_id: u32, op: u16, payload: []const u8, state: *DnsState) i32 {
    const result = resolveFromPayload(app, state, op, payload);
    var buf: [512]u8 = .{0} ** 512;
    var w = Writer{ .out = buf[0..] };
    w.text("name=");
    w.text(spanZ(result.name[0..]));
    w.text(" result=");
    w.text(dnsResultName(result.result));
    w.text(" code=");
    w.signed(result.result);
    w.text(" ip=");
    w.ip(result.answer);
    w.text(" server=");
    w.ip(result.server);
    w.text(" pending=");
    w.text(if ((result.flags & r4os.abi.net_service_dns_flag_pending) != 0) "yes" else "no");
    w.text(" cache=");
    w.text(if ((result.flags & r4os.abi.net_service_dns_flag_cache_valid) != 0) "yes" else "no");
    w.text(" cache_hits=");
    w.num(result.cache_hits);
    w.text(" cache_stores=");
    w.num(result.cache_stores);
    w.text(" timeout=");
    w.num(result.timeouts);
    w.text(" last=");
    w.text(spanZ(result.last_error[0..]));
    return r4os.app_services.replyIfPending(app.sys, handle, request_id, r4os.abi.service_api_result_ok, w.slice());
}

fn replyResolveResult(app: *const App, handle: u32, request_id: u32, op: u16, payload: []const u8, state: *DnsState) i32 {
    const result = resolveFromPayload(app, state, op, payload);
    const bytes: [*]const u8 = @ptrCast(&result);
    return r4os.app_services.replyIfPending(app.sys, handle, request_id, r4os.abi.service_api_result_ok, bytes[0..@sizeOf(r4os.abi.NetServiceDnsResult)]);
}

fn resolveFromPayload(app: *const App, state: *DnsState, op: u16, payload: []const u8) r4os.abi.NetServiceDnsResult {
    const explicit_server = op == r4os.abi.net_service_op_dns_resolve_a_server or op == r4os.abi.net_service_op_dns_resolve_a_server_result;
    var server: [4]u8 = .{0} ** 4;
    var name = payload;
    if (explicit_server) {
        if (payload.len < 5) return dnsBadRequestResult(op, "");
        server = .{ payload[0], payload[1], payload[2], payload[3] };
        name = payload[4..];
    }
    var answer: [4]u8 = .{0} ** 4;
    const before_hits = state.cache_hits;
    const result = resolveA(app, state, name, if (explicit_server) server else null, &answer);
    return makeResolveResult(app, state, op, name, result, answer, if (explicit_server) server else state.last_server, state.cache_hits > before_hits);
}

fn resolveA(app: *const App, state: *DnsState, name: []const u8, explicit_server: ?[4]u8, out: *[4]u8) i32 {
    state.resolve_requests +%= 1;
    out.* = .{0} ** 4;
    clearFixed(state.last_name[0..]);
    copyFixed(state.last_name[0..], name);

    if (!validDnsName(name)) {
        noteResult(state, name, explicit_server orelse .{0} ** 4, .{0} ** 4, r4os.abi.dns_result_name, "name");
        return r4os.abi.dns_result_name;
    }

    const server = explicit_server orelse configuredDnsServer(app, state) orelse return r4os.abi.dns_result_no_server;
    if (isZeroIp(server)) {
        noteResult(state, name, server, .{0} ** 4, r4os.abi.dns_result_no_server, "no-server");
        return r4os.abi.dns_result_no_server;
    }

    if (cacheLookup(app, state, name, server, out)) |cached| {
        noteResult(state, name, server, out.*, cached, if (cached == r4os.abi.dns_result_ok) "cache" else "cache-nxdomain");
        syncPrimaryCache(app, state);
        return cached;
    }

    var query_buf: [dns_query_max]u8 = .{0} ** dns_query_max;
    const id = nextDnsId(state);
    const query = buildAQuery(state, query_buf[0..], id, name) orelse {
        noteResult(state, name, server, .{0} ** 4, r4os.abi.dns_result_name, "query-build");
        return r4os.abi.dns_result_name;
    };

    const source_port = dnsSourcePort(id);
    const udp_handle_raw = app.net.udpBind(source_port);
    if (udp_handle_raw <= 0) {
        state.tx_errors +%= 1;
        noteResult(state, name, server, .{0} ** 4, r4os.abi.dns_result_tx, "udp-bind");
        return r4os.abi.dns_result_tx;
    }
    const udp_handle: u32 = @intCast(udp_handle_raw);
    defer _ = app.net.udpClose(udp_handle);

    const sent = app.net.udpSendTo(udp_handle, server, dns_port, query);
    if (sent < 0 or (sent != 0 and sent != @as(i32, @intCast(query.len)))) {
        state.tx_errors +%= 1;
        noteResult(state, name, server, .{0} ** 4, r4os.abi.dns_result_tx, "udp-send");
        return r4os.abi.dns_result_tx;
    }

    markPending(state, name);
    defer clearPending(state);

    const timeout_ticks = app.sys.ticksFromMilliseconds(dns_timeout_ms);
    const deadline = app.sys.ticks() + timeout_ticks;
    var response: [dns_query_max]u8 = undefined;
    while (app.sys.ticks() <= deadline) {
        var info: r4os.abi.UdpRecvInfo = .{};
        const remaining = if (deadline > app.sys.ticks()) deadline - app.sys.ticks() else 1;
        const got = app.net.udpRecvFromWait(udp_handle, &info, response[0..], remaining);
        if (got < 0) {
            state.tx_errors +%= 1;
            noteResult(state, name, server, .{0} ** 4, r4os.abi.dns_result_tx, "udp-recv");
            return r4os.abi.dns_result_tx;
        }
        if (got == 0) break;
        if (info.source_port != dns_port or !sameIp(info.source_ip, server)) continue;
        const parsed = handleResponse(state, response[0..@as(usize, @intCast(got))]);
        if (state.last_id != id) continue;
        if (parsed) {
            out.* = state.last_answer;
            cacheStore(app, state, name, server, out.*, r4os.abi.dns_result_ok);
            return r4os.abi.dns_result_ok;
        }
        if (state.last_result == r4os.abi.dns_result_nxdomain) {
            cacheStore(app, state, name, server, .{0} ** 4, r4os.abi.dns_result_nxdomain);
            return r4os.abi.dns_result_nxdomain;
        }
        return state.last_result;
    }

    state.timeouts +%= 1;
    noteResult(state, name, server, .{0} ** 4, r4os.abi.dns_result_timeout, "timeout");
    return r4os.abi.dns_result_timeout;
}

fn configuredDnsServer(app: *const App, state: *DnsState) ?[4]u8 {
    var config: r4os.abi.NetConfigSnapshot = .{};
    const rc = app.net.netConfigGet(&config);
    if (rc != r4os.abi.net_config_ok or (config.flags & r4os.abi.net_config_flag_dns_configured) == 0 or isZeroIp(config.dns_ip)) {
        noteResult(state, "", .{0} ** 4, .{0} ** 4, r4os.abi.dns_result_no_server, "no-server");
        return null;
    }
    return config.dns_ip;
}

fn makeStatusResult(app: *const App, state: *DnsState) r4os.abi.NetServiceDnsStatus {
    syncPrimaryCache(app, state);
    var flags: u32 = 0;
    if (state.last_result == r4os.abi.dns_result_ok) flags |= r4os.abi.net_service_dns_flag_ok;
    if (state.operation_pending) flags |= r4os.abi.net_service_dns_flag_pending;
    if (state.cache_valid) flags |= r4os.abi.net_service_dns_flag_cache_valid;
    var out = r4os.abi.NetServiceDnsStatus{
        .flags = flags,
        .last_result = state.last_result,
        .last_id = state.last_id,
        .last_server = state.last_server,
        .last_answer = state.last_answer,
        .cache_server = state.cache_server,
        .cache_answer = state.cache_answer,
        .cache_age_seconds = cacheAgeSeconds(app, state.cache_updated_seconds),
        .cache_ttl_seconds = state.cache_ttl_seconds,
        .cache_remaining_seconds = cacheRemainingSeconds(app, state.cache_updated_seconds, state.cache_ttl_seconds),
        .queries_tx = state.queries_tx,
        .resolve_requests = state.resolve_requests,
        .responses_rx = state.responses_rx,
        .a_records = state.a_records,
        .timeouts = state.timeouts,
        .nxdomain = state.nxdomain,
        .tx_errors = state.tx_errors,
        .malformed = state.malformed,
        .self_tests = state.self_tests,
        .cache_hits = state.cache_hits,
        .cache_stores = state.cache_stores,
    };
    copyFixed(out.name[0..], spanZ(state.last_name[0..]));
    out.name_len = @intCast(stringLenZ(out.name[0..]));
    copyFixed(out.pending_name[0..], spanZ(state.pending_name[0..]));
    out.pending_name_len = @intCast(stringLenZ(out.pending_name[0..]));
    copyFixed(out.cache_name[0..], spanZ(state.cache_name[0..]));
    out.cache_name_len = @intCast(stringLenZ(out.cache_name[0..]));
    copyFixed(out.last_error[0..], spanZ(state.last_error[0..]));
    return out;
}

fn makeResolveResult(app: *const App, state: *DnsState, op: u16, name: []const u8, result: i32, answer: [4]u8, server: [4]u8, cache_hit: bool) r4os.abi.NetServiceDnsResult {
    syncPrimaryCache(app, state);
    const explicit_server = op == r4os.abi.net_service_op_dns_resolve_a_server or op == r4os.abi.net_service_op_dns_resolve_a_server_result;
    var flags: u32 = 0;
    if (result == r4os.abi.dns_result_ok) flags |= r4os.abi.net_service_dns_flag_ok;
    if (state.operation_pending) flags |= r4os.abi.net_service_dns_flag_pending;
    if (state.cache_valid) flags |= r4os.abi.net_service_dns_flag_cache_valid;
    if (cache_hit) flags |= r4os.abi.net_service_dns_flag_cache_hit;
    if (explicit_server) flags |= r4os.abi.net_service_dns_flag_explicit_server;
    flags = withServiceStatus(flags, serviceStatusFromDnsResult(result));
    var out = r4os.abi.NetServiceDnsResult{
        .action = if (explicit_server) r4os.abi.net_service_dns_action_resolve_a_server else r4os.abi.net_service_dns_action_resolve_a,
        .result = result,
        .flags = flags,
        .answer = answer,
        .server = server,
        .cache_answer = state.cache_answer,
        .cache_age_seconds = cacheAgeSeconds(app, state.cache_updated_seconds),
        .cache_ttl_seconds = state.cache_ttl_seconds,
        .cache_remaining_seconds = cacheRemainingSeconds(app, state.cache_updated_seconds, state.cache_ttl_seconds),
        .queries_tx = state.queries_tx,
        .resolve_requests = state.resolve_requests,
        .responses_rx = state.responses_rx,
        .a_records = state.a_records,
        .timeouts = state.timeouts,
        .nxdomain = state.nxdomain,
        .tx_errors = state.tx_errors,
        .malformed = state.malformed,
        .cache_hits = state.cache_hits,
        .cache_stores = state.cache_stores,
        .last_id = state.last_id,
    };
    copyFixed(out.name[0..], name);
    out.name_len = @intCast(@min(name.len, out.name.len));
    copyFixed(out.last_error[0..], spanZ(state.last_error[0..]));
    return out;
}

fn dnsBadRequestResult(op: u16, name: []const u8) r4os.abi.NetServiceDnsResult {
    const explicit_server = op == r4os.abi.net_service_op_dns_resolve_a_server or op == r4os.abi.net_service_op_dns_resolve_a_server_result;
    var out = r4os.abi.NetServiceDnsResult{
        .action = if (explicit_server) r4os.abi.net_service_dns_action_resolve_a_server else r4os.abi.net_service_dns_action_resolve_a,
        .result = r4os.abi.dns_result_name,
        .flags = withServiceStatus(if (explicit_server) r4os.abi.net_service_dns_flag_explicit_server else 0, r4os.abi.net_service_status_failed),
    };
    copyFixed(out.name[0..], name);
    out.name_len = @intCast(@min(name.len, out.name.len));
    copyFixed(out.last_error[0..], "bad-request");
    return out;
}

fn runPing(app: *const App) i32 {
    app.sys.println("DNSSVC ping");
    var handle: u32 = 0;
    if (!ensureRunningAndOpen(app, &handle)) {
        app.sys.println("DNSSVC ping failed");
        return 1;
    }
    defer _ = app.sys.serviceClose(handle);

    var header: r4os.abi.ServiceMessageHeader = .{};
    var response: [@sizeOf(r4os.abi.NetServiceDnsStatus)]u8 = undefined;
    const got = app.sys.serviceCall(handle, r4os.abi.net_service_op_dns_status_result, "", &header, response[0..], app.sys.ticksFromMilliseconds(1000));
    if (got != @as(i32, @intCast(@sizeOf(r4os.abi.NetServiceDnsStatus))) or header.status != r4os.abi.service_api_result_ok) {
        app.sys.println("DNSSVC ping failed");
        return 1;
    }
    var status = r4os.abi.NetServiceDnsStatus{};
    copyStruct(&status, response[0..]);
    if (status.magic != r4os.abi.net_service_dns_status_magic or status.version != r4os.abi.net_service_dns_status_version) {
        app.sys.println("DNSSVC ping failed");
        return 1;
    }
    app.sys.println("DNSSVC ping: OK");
    return 0;
}

fn runSelfTest(app: *const App) i32 {
    app.sys.println("DNSSVC selftest");
    if (!app.sys.hasFn("service_start")) return fail(app, "manager-api");
    if (!app.sys.hasFn("service_call")) return fail(app, "service-api");
    if (!localContractSelfTest(app)) return fail(app, "local-contract");

    var handle: u32 = 0;
    if (!ensureRunningAndOpen(app, &handle)) return fail(app, "open");
    defer _ = app.sys.serviceClose(handle);

    var header: r4os.abi.ServiceMessageHeader = .{};
    var status_response: [@sizeOf(r4os.abi.NetServiceDnsStatus)]u8 = undefined;
    const status_got = app.sys.serviceCall(handle, r4os.abi.net_service_op_dns_status_result, "", &header, status_response[0..], app.sys.ticksFromMilliseconds(1000));
    if (status_got != @as(i32, @intCast(@sizeOf(r4os.abi.NetServiceDnsStatus))) or header.status != r4os.abi.service_api_result_ok) return fail(app, "status");
    var status = r4os.abi.NetServiceDnsStatus{};
    copyStruct(&status, status_response[0..]);
    if (status.magic != r4os.abi.net_service_dns_status_magic or status.version != r4os.abi.net_service_dns_status_version) return fail(app, "status-magic");

    var bad_response: [@sizeOf(r4os.abi.NetServiceDnsResult)]u8 = undefined;
    const bad_got = app.sys.serviceCall(handle, r4os.abi.net_service_op_dns_resolve_a_server_result, "\x00\x00\x00\x00example.invalid", &header, bad_response[0..], app.sys.ticksFromMilliseconds(1000));
    if (bad_got != @as(i32, @intCast(@sizeOf(r4os.abi.NetServiceDnsResult))) or header.status != r4os.abi.service_api_result_ok) return fail(app, "bad-server-call");
    var bad_result = r4os.abi.NetServiceDnsResult{};
    copyStruct(&bad_result, bad_response[0..]);
    if (bad_result.result != r4os.abi.dns_result_no_server) return fail(app, "bad-server-result");

    var response_header: r4os.abi.ServiceMessageHeader = .{};
    var small: [8]u8 = .{0} ** 8;
    const bad_op = app.sys.serviceCall(handle, 0xFFFF, "", &response_header, small[0..], app.sys.ticksFromMilliseconds(100));
    if (bad_op < 0 or response_header.status != r4os.abi.service_api_result_bad_op) return fail(app, "bad-op");

    app.sys.println("DNSSVC selftest: OK");
    return 0;
}

fn localContractSelfTest(app: *const App) bool {
    var state = DnsState{};
    var query: [128]u8 = .{0} ** 128;
    const q = buildAQuery(&state, query[0..], 0x444E, "r4os.test") orelse return false;
    var response: [192]u8 = .{0} ** 192;
    const r = buildSyntheticResponse(response[0..], q, .{ 10, 0, 2, 2 }) orelse return false;
    if (!handleResponse(&state, r)) return false;
    if (state.last_result != r4os.abi.dns_result_ok or !sameIp(state.last_answer, .{ 10, 0, 2, 2 })) return false;
    const cr = buildSyntheticCnameResponse(response[0..], q, .{ 10, 0, 2, 9 }) orelse return false;
    if (!handleResponse(&state, cr)) return false;
    if (!sameIp(state.last_answer, .{ 10, 0, 2, 9 })) return false;
    const nr = buildSyntheticNxDomain(response[0..], q) orelse return false;
    if (handleResponse(&state, nr)) return false;
    if (state.last_result != r4os.abi.dns_result_nxdomain or state.nxdomain == 0) return false;
    if (handleResponse(&state, (&[_]u8{ 1, 2, 3 })[0..])) return false;
    cacheStore(app, &state, "r4os.test", .{ 10, 0, 2, 3 }, .{ 10, 0, 2, 2 }, r4os.abi.dns_result_ok);
    cacheStore(app, &state, "missing.r4os", .{ 10, 0, 2, 3 }, .{0} ** 4, r4os.abi.dns_result_nxdomain);
    var out: [4]u8 = .{0} ** 4;
    if ((cacheLookup(app, &state, "R4OS.TEST", .{ 10, 0, 2, 3 }, &out) orelse r4os.abi.dns_result_timeout) != r4os.abi.dns_result_ok) return false;
    if (!sameIp(out, .{ 10, 0, 2, 2 })) return false;
    if ((cacheLookup(app, &state, "missing.r4os", .{ 10, 0, 2, 3 }, &out) orelse r4os.abi.dns_result_timeout) != r4os.abi.dns_result_nxdomain) return false;
    state.cache[0].updated_seconds = 0;
    state.cache[0].ttl_seconds = 0;
    if (cacheEntryFresh(app, state.cache[0])) return false;
    state.self_tests +%= 1;
    return state.cache_stores >= 2 and state.cache_hits >= 2 and state.malformed != 0;
}

fn ensureRunningAndOpen(app: *const App, out_handle: *u32) bool {
    var info: r4os.abi.ServiceInfo = .{};
    const status = app.sys.serviceStatus(service_name, &info);
    if (status != r4os.abi.service_api_result_ok) return false;
    if (info.state != r4os.abi.service_state_running) {
        const start = app.sys.serviceStart(service_name, &info);
        if (start != r4os.abi.service_api_result_ok) return false;
    }
    var tick: u32 = 0;
    while (tick < 160) : (tick += 1) {
        const open_rc = app.sys.serviceOpen(service_name, &info);
        if (open_rc == r4os.abi.service_api_result_ok and info.handle != 0) {
            out_handle.* = info.handle;
            return true;
        }
        app.sys.sleepTicks(1);
    }
    return false;
}

fn buildAQuery(state: *DnsState, out: []u8, id: u16, name: []const u8) ?[]u8 {
    if (out.len < 18) return null;
    @memset(out, 0);
    writeBe16(out, 0, id);
    writeBe16(out, 2, 0x0100);
    writeBe16(out, 4, 1);
    var pos: usize = 12;
    pos = writeName(out, pos, name) orelse return null;
    if (pos + 4 > out.len) return null;
    writeBe16(out, pos, dns_type_a);
    writeBe16(out, pos + 2, dns_class_in);
    state.queries_tx +%= 1;
    state.last_id = id;
    state.last_result = 1;
    setLastError(state, "query");
    return out[0 .. pos + 4];
}

fn handleResponse(state: *DnsState, payload: []const u8) bool {
    if (payload.len < 12) return badResponse(state, "short", r4os.abi.dns_result_short);
    const id = readBe16(payload, 0);
    const flags = readBe16(payload, 2);
    const qd = readBe16(payload, 4);
    const an = readBe16(payload, 6);
    const rcode = flags & 0x000F;
    state.last_id = id;
    if (rcode == 3) {
        state.nxdomain +%= 1;
        state.last_result = r4os.abi.dns_result_nxdomain;
        setLastError(state, "nxdomain");
        return false;
    }
    if ((flags & 0x8000) == 0 or qd == 0 or an == 0 or rcode != 0) return badResponse(state, "header", r4os.abi.dns_result_header);
    var pos: usize = 12;
    pos = skipName(payload, pos) orelse return badResponse(state, "qname", r4os.abi.dns_result_qname);
    if (pos + 4 > payload.len) return badResponse(state, "question", r4os.abi.dns_result_question);
    pos += 4;
    var answer_index: u16 = 0;
    while (answer_index < an) : (answer_index += 1) {
        pos = skipName(payload, pos) orelse return badResponse(state, "aname", r4os.abi.dns_result_aname);
        if (pos + 10 > payload.len) return badResponse(state, "answer", r4os.abi.dns_result_answer);
        const typ = readBe16(payload, pos);
        const class = readBe16(payload, pos + 2);
        const rdlen: usize = @intCast(readBe16(payload, pos + 8));
        pos += 10;
        if (pos + rdlen > payload.len) return badResponse(state, "answer", r4os.abi.dns_result_answer);
        if (typ == dns_type_a) {
            if (class != dns_class_in or rdlen != 4) return badResponse(state, "atype", r4os.abi.dns_result_atype);
            state.responses_rx +%= 1;
            state.a_records +%= 1;
            state.last_id = id;
            state.last_result = r4os.abi.dns_result_ok;
            state.last_answer = .{ payload[pos], payload[pos + 1], payload[pos + 2], payload[pos + 3] };
            setLastError(state, "answer");
            return true;
        }
        pos += rdlen;
    }
    return badResponse(state, "atype", r4os.abi.dns_result_atype);
}

fn badResponse(state: *DnsState, reason: []const u8, result: i32) bool {
    state.malformed +%= 1;
    state.last_result = result;
    setLastError(state, reason);
    return false;
}

fn writeName(out: []u8, pos_in: usize, name: []const u8) ?usize {
    var pos = pos_in;
    var label_start: usize = 0;
    var i: usize = 0;
    while (i <= name.len) : (i += 1) {
        if (i == name.len or name[i] == '.') {
            const len = i - label_start;
            if (len == 0 or len > 63 or pos + 1 + len >= out.len) return null;
            out[pos] = @intCast(len);
            pos += 1;
            var j = label_start;
            while (j < i) : (j += 1) {
                out[pos] = name[j];
                pos += 1;
            }
            label_start = i + 1;
        }
    }
    if (pos >= out.len) return null;
    out[pos] = 0;
    return pos + 1;
}

fn skipName(payload: []const u8, pos_in: usize) ?usize {
    var pos = pos_in;
    var guard: usize = 0;
    while (pos < payload.len and guard < 128) : (guard += 1) {
        const len = payload[pos];
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= payload.len) return null;
            return pos + 2;
        }
        if ((len & 0xC0) != 0) return null;
        if (len == 0) return pos + 1;
        if (pos + 1 + len > payload.len) return null;
        pos += 1 + len;
    }
    return null;
}

fn cacheLookup(app: *const App, state: *DnsState, name: []const u8, server: [4]u8, out: *[4]u8) ?i32 {
    var i: usize = 0;
    while (i < state.cache.len) : (i += 1) {
        const entry = state.cache[i];
        if (!entry.valid) continue;
        if (!cacheEntryFresh(app, entry)) {
            if (!queryPinned(app, state, &state.cache[i])) state.cache[i] = .{};
            continue;
        }
        if (entry.query_port != dns_port or !sameIp(entry.server, server) or !equalsIgnoreCase(spanZ(entry.name[0..]), name)) continue;
        state.cache_hits +%= 1;
        out.* = entry.answer;
        syncPrimaryCacheFromEntry(state, entry);
        return if (entry.negative) r4os.abi.dns_result_nxdomain else r4os.abi.dns_result_ok;
    }
    return null;
}

fn cacheStore(app: *const App, state: *DnsState, name: []const u8, server: [4]u8, answer: [4]u8, result: i32) void {
    const index = cacheFindSlot(app, state, name, server) orelse cacheReplacementSlot(app, state) orelse return;
    state.cache[index] = .{
        .valid = true,
        .negative = result == r4os.abi.dns_result_nxdomain,
        .server = server,
        .answer = answer,
        .updated_seconds = nowSeconds(app),
        .ttl_seconds = if (result == r4os.abi.dns_result_nxdomain) dns_negative_ttl_seconds else dns_default_ttl_seconds,
    };
    copyFixed(state.cache[index].name[0..], name);
    state.cache_stores +%= 1;
    syncPrimaryCacheFromEntry(state, state.cache[index]);
}

fn cacheFindSlot(app: *const App, state: *DnsState, name: []const u8, server: [4]u8) ?usize {
    var i: usize = 0;
    while (i < state.cache.len) : (i += 1) {
        const entry = state.cache[i];
        if (!entry.valid or queryPinned(app, state, &state.cache[i])) continue;
        if (!cacheEntryFresh(app, entry)) {
            if (!queryPinned(app, state, &state.cache[i])) state.cache[i] = .{};
            continue;
        }
        if (sameIp(entry.server, server) and equalsIgnoreCase(spanZ(entry.name[0..]), name)) return i;
    }
    return null;
}

fn cacheReplacementSlot(app: *const App, state: *DnsState) ?usize {
    for (0..state.cache.len) |i| {
        if (queryPinned(app, state, &state.cache[i])) continue;
        if (!state.cache[i].valid or !cacheEntryFresh(app, state.cache[i])) {
            state.cache_next = (i + 1) % state.cache.len;
            return i;
        }
    }
    for (0..state.cache.len) |offset| {
        const i = (state.cache_next + offset) % state.cache.len;
        if (queryPinned(app, state, &state.cache[i])) continue;
        state.cache_next = (i + 1) % state.cache.len;
        return i;
    }
    return null;
}

fn cacheEntryFresh(app: *const App, entry: DnsCacheEntry) bool {
    if (!entry.valid) return false;
    const now = nowSeconds(app);
    if (now < entry.updated_seconds) return false;
    return now - entry.updated_seconds < entry.ttl_seconds;
}

fn syncPrimaryCache(app: *const App, state: *DnsState) void {
    var i: usize = 0;
    while (i < state.cache.len) : (i += 1) {
        const entry = state.cache[i];
        if (!entry.valid or !cacheEntryFresh(app, entry)) continue;
        syncPrimaryCacheFromEntry(state, entry);
        return;
    }
    state.cache_valid = false;
    clearFixed(state.cache_name[0..]);
    state.cache_server = .{0} ** 4;
    state.cache_answer = .{0} ** 4;
    state.cache_updated_seconds = 0;
    state.cache_ttl_seconds = dns_default_ttl_seconds;
}

fn syncPrimaryCacheFromEntry(state: *DnsState, entry: DnsCacheEntry) void {
    state.cache_valid = entry.valid;
    copyFixed(&state.cache_name, spanZ(&entry.name));
    state.cache_server = entry.server;
    state.cache_answer = entry.answer;
    state.cache_updated_seconds = entry.updated_seconds;
    state.cache_ttl_seconds = entry.ttl_seconds;
}

fn markPending(state: *DnsState, name: []const u8) void {
    state.operation_pending = true;
    clearFixed(state.pending_name[0..]);
    copyFixed(state.pending_name[0..], name);
}

fn clearPending(state: *DnsState) void {
    state.operation_pending = false;
    clearFixed(state.pending_name[0..]);
}

fn noteResult(state: *DnsState, name: []const u8, server: [4]u8, answer: [4]u8, result: i32, err_text: []const u8) void {
    state.last_result = result;
    state.last_server = server;
    state.last_answer = answer;
    clearFixed(state.last_name[0..]);
    copyFixed(state.last_name[0..], name);
    setLastError(state, err_text);
}

fn writeStatusText(w: *Writer, app: *const App, state: *const DnsState) void {
    w.text("pending=");
    w.text(if (state.operation_pending) "yes" else "no");
    w.text(" name=");
    w.text(if (state.operation_pending) spanZ(state.pending_name[0..]) else spanZ(state.last_name[0..]));
    w.text(" queries=");
    w.num(state.queries_tx);
    w.text(" resolve=");
    w.num(state.resolve_requests);
    w.text(" responses=");
    w.num(state.responses_rx);
    w.text(" a=");
    w.num(state.a_records);
    w.text(" timeout=");
    w.num(state.timeouts);
    w.text(" nxdomain=");
    w.num(state.nxdomain);
    w.text(" txerr=");
    w.num(state.tx_errors);
    w.text(" malformed=");
    w.num(state.malformed);
    w.text(" server=");
    w.ip(state.last_server);
    w.text(" id=");
    w.num(state.last_id);
    w.text(" answer=");
    w.ip(state.last_answer);
    w.text(" result=");
    w.signed(state.last_result);
    w.text(" cache=");
    w.text(if (state.cache_valid) "yes" else "no");
    w.text(" cache_name=");
    w.text(spanZ(state.cache_name[0..]));
    w.text(" cache_answer=");
    w.ip(state.cache_answer);
    w.text(" cache_hits=");
    w.num(state.cache_hits);
    w.text(" cache_stores=");
    w.num(state.cache_stores);
    w.text(" cache_age=");
    w.num(cacheAgeSeconds(app, state.cache_updated_seconds));
    w.text("/");
    w.num(state.cache_ttl_seconds);
    w.text(" cache_remaining=");
    w.num(cacheRemainingSeconds(app, state.cache_updated_seconds, state.cache_ttl_seconds));
    w.text(" last=");
    w.text(spanZ(state.last_error[0..]));
}

fn buildSyntheticResponse(out: []u8, query: []const u8, answer: [4]u8) ?[]u8 {
    if (query.len + 16 > out.len or query.len < 12) return null;
    copyBytes(out[0..query.len], query);
    writeBe16(out, 2, 0x8180);
    writeBe16(out, 6, 1);
    const pos = query.len;
    out[pos] = 0xC0;
    out[pos + 1] = 0x0C;
    writeBe16(out, pos + 2, dns_type_a);
    writeBe16(out, pos + 4, dns_class_in);
    writeBe32(out, pos + 6, 60);
    writeBe16(out, pos + 10, 4);
    out[pos + 12] = answer[0];
    out[pos + 13] = answer[1];
    out[pos + 14] = answer[2];
    out[pos + 15] = answer[3];
    return out[0 .. pos + 16];
}

fn buildSyntheticCnameResponse(out: []u8, query: []const u8, answer: [4]u8) ?[]u8 {
    if (query.len + 34 > out.len or query.len < 12) return null;
    copyBytes(out[0..query.len], query);
    writeBe16(out, 2, 0x8180);
    writeBe16(out, 6, 2);
    var pos = query.len;
    out[pos] = 0xC0;
    out[pos + 1] = 0x0C;
    writeBe16(out, pos + 2, dns_type_cname);
    writeBe16(out, pos + 4, dns_class_in);
    writeBe32(out, pos + 6, 60);
    writeBe16(out, pos + 10, 6);
    out[pos + 12] = 3;
    out[pos + 13] = 'a';
    out[pos + 14] = 'l';
    out[pos + 15] = 't';
    out[pos + 16] = 0xC0;
    out[pos + 17] = 0x0C;
    pos += 18;
    out[pos] = 0xC0;
    out[pos + 1] = 0x0C;
    writeBe16(out, pos + 2, dns_type_a);
    writeBe16(out, pos + 4, dns_class_in);
    writeBe32(out, pos + 6, 60);
    writeBe16(out, pos + 10, 4);
    out[pos + 12] = answer[0];
    out[pos + 13] = answer[1];
    out[pos + 14] = answer[2];
    out[pos + 15] = answer[3];
    return out[0 .. pos + 16];
}

fn buildSyntheticNxDomain(out: []u8, query: []const u8) ?[]u8 {
    if (query.len > out.len or query.len < 12) return null;
    copyBytes(out[0..query.len], query);
    writeBe16(out, 2, 0x8183);
    writeBe16(out, 6, 0);
    return out[0..query.len];
}

fn validDnsName(name: []const u8) bool {
    if (name.len == 0 or name.len >= dns_name_max) return false;
    var label_len: usize = 0;
    for (name) |ch| {
        if (ch == '.') {
            if (label_len == 0 or label_len > 63) return false;
            label_len = 0;
            continue;
        }
        if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '-')) return false;
        label_len += 1;
    }
    return label_len != 0 and label_len <= 63;
}

fn nextDnsId(state: *DnsState) u16 {
    state.next_id +%= 1;
    if (state.next_id == 0) state.next_id = 0x4400;
    return state.next_id;
}

fn dnsSourcePort(id: u16) u16 {
    return dns_source_port_base + (id & 0x03FF);
}

fn serviceStatusFromDnsResult(result: i32) u32 {
    return switch (result) {
        r4os.abi.dns_result_ok => r4os.abi.net_service_status_ok,
        r4os.abi.dns_result_timeout => r4os.abi.net_service_status_timeout,
        else => r4os.abi.net_service_status_failed,
    };
}

fn withServiceStatus(flags: u32, status: u32) u32 {
    return (flags & ~r4os.abi.net_service_status_mask) | (status << r4os.abi.net_service_status_shift);
}

fn nowSeconds(app: *const App) u64 {
    const hz = app.sys.monotonicHz();
    if (hz == 0) return 0;
    return app.sys.ticks() / hz;
}

fn cacheAgeSeconds(app: *const App, updated: u64) u32 {
    const now = nowSeconds(app);
    if (updated == 0 or now <= updated) return 0;
    const age = now - updated;
    return if (age > 0xFFFF_FFFF) 0xFFFF_FFFF else @intCast(age);
}

fn cacheRemainingSeconds(app: *const App, updated: u64, ttl: u32) u32 {
    const age = cacheAgeSeconds(app, updated);
    return if (age >= ttl) 0 else ttl - age;
}

fn dnsResultName(result: i32) []const u8 {
    return switch (result) {
        r4os.abi.dns_result_ok => "ok",
        r4os.abi.dns_result_short => "short",
        r4os.abi.dns_result_header => "header",
        r4os.abi.dns_result_qname => "qname",
        r4os.abi.dns_result_question => "question",
        r4os.abi.dns_result_aname => "aname",
        r4os.abi.dns_result_answer => "answer",
        r4os.abi.dns_result_atype => "atype",
        r4os.abi.dns_result_buffer_small => "buffer-small",
        r4os.abi.dns_result_name => "name",
        r4os.abi.dns_result_nxdomain => "nxdomain",
        r4os.abi.dns_result_timeout => "timeout",
        r4os.abi.dns_result_no_server => "no-server",
        r4os.abi.dns_result_tx => "tx-error",
        else => "unknown",
    };
}

fn fail(app: *const App, label: []const u8) i32 {
    app.sys.write("DNSSVC selftest FAILED: ");
    app.sys.println(label);
    return 1;
}

fn hasArg(args: [*:0]const u8, wanted: []const u8) bool {
    var offset: usize = 0;
    while (offset < 256 and args[offset] != 0) {
        while (offset < 256 and (args[offset] == ' ' or args[offset] == '\t')) : (offset += 1) {}
        const start = offset;
        while (offset < 256 and args[offset] != 0 and args[offset] != ' ' and args[offset] != '\t') : (offset += 1) {}
        if (equalsIgnoreCase(args[start..offset], wanted)) return true;
    }
    return false;
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (upper(a[i]) != upper(b[i])) return false;
    }
    return true;
}

fn upper(ch: u8) u8 {
    if (ch >= 'a' and ch <= 'z') return ch - ('a' - 'A');
    return ch;
}

fn sameIp(a: [4]u8, b: [4]u8) bool {
    return a[0] == b[0] and a[1] == b[1] and a[2] == b[2] and a[3] == b[3];
}

fn isZeroIp(ip: [4]u8) bool {
    return ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] == 0;
}

fn copyFixed(out: []u8, value: []const u8) void {
    clearFixed(out);
    if (out.len == 0) return;
    const len = @min(value.len, out.len - 1);
    if (len != 0) copyBytes(out[0..len], value[0..len]);
}

fn clearFixed(out: []u8) void {
    @memset(out, 0);
}

fn setLastError(state: *DnsState, value: []const u8) void {
    copyFixed(state.last_error[0..], value);
}

fn copyBytes(out: []u8, value: []const u8) void {
    var i: usize = 0;
    while (i < out.len and i < value.len) : (i += 1) out[i] = value[i];
}

fn copyStruct(out: anytype, data: []const u8) void {
    const out_bytes: [*]u8 = @ptrCast(out);
    const size = @sizeOf(@TypeOf(out.*));
    const len = @min(size, data.len);
    var i: usize = 0;
    while (i < len) : (i += 1) out_bytes[i] = data[i];
}

fn spanZ(value: []const u8) []const u8 {
    return value[0..stringLenZ(value)];
}

fn stringLenZ(value: []const u8) usize {
    var len: usize = 0;
    while (len < value.len and value[len] != 0) : (len += 1) {}
    return len;
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    return (@as(u16, buf[offset]) << 8) | buf[offset + 1];
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @intCast(value >> 8);
    buf[offset + 1] = @intCast(value & 0xFF);
}

fn writeBe32(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @intCast(value >> 24);
    buf[offset + 1] = @intCast((value >> 16) & 0xFF);
    buf[offset + 2] = @intCast((value >> 8) & 0xFF);
    buf[offset + 3] = @intCast(value & 0xFF);
}

const Writer = struct {
    out: []u8,
    pos: usize = 0,

    fn put(self: *Writer, ch: u8) void {
        if (self.pos >= self.out.len) return;
        self.out[self.pos] = ch;
        self.pos += 1;
    }

    fn text(self: *Writer, value: []const u8) void {
        for (value) |ch| if (ch != 0) self.put(ch);
    }

    fn slice(self: *const Writer) []const u8 {
        return self.out[0..self.pos];
    }

    fn num(self: *Writer, value: anytype) void {
        var buf: [20]u8 = undefined;
        var pos: usize = buf.len;
        var n: u64 = @intCast(value);
        if (n == 0) {
            self.put('0');
            return;
        }
        while (n > 0) {
            pos -= 1;
            buf[pos] = '0' + @as(u8, @intCast(n % 10));
            n /= 10;
        }
        self.text(buf[pos..]);
    }

    fn signed(self: *Writer, value: i32) void {
        if (value < 0) {
            self.put('-');
            self.num(@as(u32, @intCast(-value)));
        } else {
            self.num(@as(u32, @intCast(value)));
        }
    }

    fn ip(self: *Writer, value: [4]u8) void {
        self.num(value[0]);
        self.put('.');
        self.num(value[1]);
        self.put('.');
        self.num(value[2]);
        self.put('.');
        self.num(value[3]);
    }
};

fn replyNetwork(app: *const App, endpoint: u32, request_id: u32, state: *DnsState, owner: u32, op: u16, payload: []const u8) i32 {
    const rc = networkRequest(app, endpoint, request_id, state, owner, op, payload) catch |err|
        r4os.app_services.replyIfPending(app.sys, endpoint, request_id, network.code(err), "");
    return if (rc == r4os.abi.service_api_result_not_found) 0 else rc;
}
fn advanceQueries(state: *DnsState, now: r4os.time_contract.checked.ClockSample) void {
    const changed = if (state.typed_clock) |old| !std.meta.eql(old.identity, now.identity) or now.instant_ns < old.instant_ns else false;
    for (&state.cache) |*entry| {
        if (entry.query_id == 0) continue;
        if (changed) {
            entry.* = .{};
            continue;
        }
        if (now.instant_ns >= entry.query_expires_ns) {
            entry.query_id = 0;
            entry.query_owner = 0;
        }
    }
    state.typed_clock = now;
}
fn queryPinned(app: *const App, state: *const DnsState, entry: *const DnsCacheEntry) bool {
    if (entry.query_id == 0) return false;
    const old = state.typed_clock orelse return true;
    const now = network.sample(app.sys) catch return true;
    if (network.ownerGone(app.sys, .{ .instance_id = entry.query_owner, .generation = entry.query_owner_generation })) return false;
    return std.meta.eql(old.identity, now.identity) and now.instant_ns >= old.instant_ns and now.instant_ns < entry.query_expires_ns;
}
fn networkRequest(app: *const App, endpoint: u32, request_id: u32, state: *DnsState, owner: u32, op: u16, payload: []const u8) network.Error!i32 {
    const a = r4os.abi;
    if (state.provider == 0) return error.Backend;
    if (op == a.network_op_info) {
        if (payload.len != 0) return error.Invalid;
        const info: a.NetworkProviderInfo = .{ .provider = state.provider, .capabilities = a.network_cap_ipv4 | a.network_cap_dns_a | a.network_cap_dns_aaaa_codec, .max_answers = 32, .page_capacity = 16 };
        return r4os.app_services.replyIfPending(app.sys, endpoint, request_id, 0, std.mem.asBytes(&info));
    }
    if (op != a.network_op_resolve and op != a.network_op_release) return error.UnsupportedPolicy;
    const req = try network.record(a.NetworkResolveRequest, payload);
    if (req.provider != state.provider) return error.ProviderChanged;
    const process = try network.owner(app.sys, owner);
    const now = try network.sample(app.sys);
    advanceQueries(state, now);
    for (&state.cache) |*entry| {
        if (entry.query_id != 0 and !queryPinned(app, state, entry)) {
            entry.query_id = 0;
            entry.query_owner = 0;
        }
    }
    if (req.query != 0) {
        const expected: a.NetworkResolveRequest = .{ .provider = req.provider, .query = req.query, .family = 0, .cursor = if (op == a.network_op_release) 0 else req.cursor, .capacity = if (op == a.network_op_release) 0 else req.capacity };
        if (!std.mem.eql(u8, std.mem.asBytes(&req), std.mem.asBytes(&expected))) return error.Invalid;
        for (&state.cache) |*entry| {
            if (entry.query_id != req.query or entry.query_owner != owner or entry.query_owner_generation != process.generation) continue;
            if (op == a.network_op_release) {
                entry.query_id = 0;
                entry.query_owner = 0;
                return r4os.app_services.replyIfPending(app.sys, endpoint, request_id, 0, "");
            }
            return networkPage(app, endpoint, request_id, state, entry, req.cursor, req.capacity);
        }
        return error.NotFound;
    }
    if (op == a.network_op_release or req.cursor != 0 or req.capacity == 0 or req.capacity > 16 or req.reserved != 0 or req.name_len == 0 or req.name_len > 254 or !std.mem.allEqual(u8, req.name[req.name_len..], 0)) return error.Invalid;
    try network.policy(req.policy);
    if (req.family != 4) return if (req.family == 6) error.UnsupportedFamily else error.Invalid;
    const limit = try network.tickDeadline(app.sys, req.deadline);
    var server = req.server;
    if (std.mem.allEqual(u8, std.mem.asBytes(&server), 0)) server = network.v4Endpoint(configuredDnsServer(app, state) orelse return error.Backend, dns_port);
    const ip = try network.ipv4(server, false);
    if (std.mem.allEqual(u8, &ip, 0)) return error.Invalid;
    if (state.next_query == 0) return error.Capacity;
    // Reserve one original cache entry before any network work. Pinned pages
    // are immutable and never evicted by a legacy cache replacement.
    const slot = cacheReplacementSlot(app, state) orelse return error.Capacity;
    const name = req.name[0..req.name_len];
    var query_buffer: [512]u8 = undefined;
    const id = nextDnsId(state);
    const query_length = dns_codec.buildQuery(id, name, .ipv4, &query_buffer) catch return error.Invalid;
    const raw = app.net.udpBind(dnsSourcePort(id));
    if (raw <= 0) return error.Backend;
    const socket: u32 = @intCast(raw);
    defer _ = app.net.udpClose(socket);
    const sent = app.net.udpSendTo(socket, ip, server.port, query_buffer[0..query_length]);
    if (sent != 0 and sent != query_length) return error.Backend;
    state.queries_tx +%= 1;
    state.resolve_requests +%= 1;
    const operation_limit = std.math.add(u64, app.sys.ticks(), app.sys.ticksFromMilliseconds(dns_timeout_ms)) catch return error.Invalid;
    const tick_limit = if (limit) |value| @min(value, operation_limit) else operation_limit;
    var response: [dns_codec.max_message]u8 = undefined;
    var answers: dns_codec.Answer = .{};
    while (true) {
        try network.checkAttempt(app.sys, req.deadline);
        if (app.sys.ticks() >= tick_limit) {
            state.timeouts +%= 1;
            return error.Timeout;
        }
        var info: a.UdpRecvInfo = .{};
        const got = app.net.udpRecvFrom(socket, &info, &response);
        if (got < 0) return error.Backend;
        if (got > 0 and info.source_port == server.port and sameIp(info.source_ip, ip)) {
            state.responses_rx +%= 1;
            dns_codec.parseResponse(response[0..@intCast(got)], id, name, .ipv4, &answers) catch |err| switch (err) {
                error.Mismatch => continue,
                error.Truncated => return error.TruncatedDns,
                error.NotFound, error.NoData => return error.NotFound,
                error.Capacity => return error.Capacity,
                else => {
                    state.malformed +%= 1;
                    return error.Invalid;
                },
            };
            break;
        }
        app.sys.sleepTicks(1);
    }
    // Recheck exact source clock/deadline before publishing copied results.
    try network.checkAttempt(app.sys, req.deadline);
    if (!network.ownerAlive(app.sys, process)) return error.BadSocket;
    const completed = try network.sample(app.sys);
    advanceQueries(state, completed);
    const expiry = std.math.add(u64, completed.instant_ns, a.network_lease_ns) catch return error.Capacity;
    const query = state.next_query;
    state.next_query = std.math.add(u64, query, 1) catch 0;
    state.cache[slot] = .{ .valid = true, .server = ip, .answer = answers.addresses[0].bytes[0..4].*, .updated_seconds = nowSeconds(app), .ttl_seconds = answers.ttl_seconds, .query_id = query, .query_owner = owner, .query_owner_generation = process.generation, .query_expires_ns = expiry, .query_answers = answers, .query_port = server.port };
    copyFixed(&state.cache[slot].name, name);
    state.cache_stores +%= 1;
    state.a_records +%= answers.count;
    const rc = try networkPage(app, endpoint, request_id, state, &state.cache[slot], 0, req.capacity);
    if (rc == a.service_api_result_not_found) {
        state.cache[slot].query_id = 0;
        state.cache[slot].query_owner = 0;
        return 0;
    }
    return rc;
}
fn networkPage(app: *const App, endpoint: u32, request_id: u32, state: *DnsState, entry: *const DnsCacheEntry, cursor: u32, capacity: u32) network.Error!i32 {
    const a = r4os.abi;
    if (capacity == 0 or capacity > 16 or cursor >= entry.query_answers.count) return error.Invalid;
    const count = @min(capacity, entry.query_answers.count - cursor);
    const next = cursor + count;
    const page: a.NetworkResolvePage = .{ .provider = state.provider, .query = entry.query_id, .expires_ns = entry.query_expires_ns, .next = @intCast(next), .count = @intCast(count), .total = @intCast(entry.query_answers.count), .flags = if (next < entry.query_answers.count) a.network_flag_more else 0 };
    var response: [4096]u8 = undefined;
    @memcpy(response[0..@sizeOf(a.NetworkResolvePage)], std.mem.asBytes(&page));
    for (0..count) |i| {
        const source = entry.query_answers.addresses[cursor + i];
        const address: a.NetworkResolveAnswer = .{ .address = .{ .family = @intFromEnum(source.family), .bytes = source.bytes }, .ttl_seconds = @min(source.ttl_seconds, entry.query_answers.ttl_seconds) };
        @memcpy(response[@sizeOf(a.NetworkResolvePage) + i * @sizeOf(a.NetworkResolveAnswer) ..][0..@sizeOf(a.NetworkResolveAnswer)], std.mem.asBytes(&address));
    }
    // Unlike the normal helper, preserve NOT_FOUND so a lost initial reply
    // can release its newly created page lease without leaking a cache slot.
    return app.sys.serviceEndpointReply(endpoint, request_id, 0, response[0 .. @sizeOf(a.NetworkResolvePage) + count * @sizeOf(a.NetworkResolveAnswer)]);
}
