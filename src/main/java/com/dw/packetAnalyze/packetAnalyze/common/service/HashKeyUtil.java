package com.dw.packetAnalyze.packetAnalyze.common.service;

import java.util.Arrays;
import java.util.zip.CRC32;

public class HashKeyUtil {

  private static final ThreadLocal<CRC32> CRC32_LOCAL = ThreadLocal.withInitial(CRC32::new);

  private static void reset() {
    CRC32_LOCAL.get().reset();
  }

  private static void update(byte[] data) {
    if (data != null) {
      CRC32_LOCAL.get().update(data, 0, data.length);
    }
  }

  private static void updateInt(int value) {
    CRC32_LOCAL.get().update((value) & 0xFF);
    CRC32_LOCAL.get().update((value >>> 8) & 0xFF);
    CRC32_LOCAL.get().update((value >>> 16) & 0xFF);
    CRC32_LOCAL.get().update((value >>> 24) & 0xFF);
  }

  private static long getValue() {
    return CRC32_LOCAL.get().getValue();
  }

  public static long ehterUniqueKey(byte[] dstMac, int vlan, byte[] payload) {
    reset();
    update(dstMac);
    updateInt(vlan);
    update(payload);
    return getValue();
  }

  public static long ipKey(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort, int identification) {
    reset();
    update(srcIp);
    update(dstIp);
    updateInt(srcPort);
    updateInt(dstPort);
    updateInt(identification);
    return getValue();
  }

  public static long ipSessionDirectionKey(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
    byte[] a = flatten(srcIp, srcPort);
    byte[] b = flatten(dstIp, dstPort);
    reset();
    update(a);
    update(b);
    return getValue();
  }

  private static byte[] flatten(byte[] ip, int port) {
    byte[] res = new byte[ip.length + 4];
    int idx = 0;
    System.arraycopy(ip, 0, res, idx, ip.length);
    idx += ip.length;
    res[idx++] = (byte) ((port >> 24) & 0xFF);
    res[idx++] = (byte) ((port >> 16) & 0xFF);
    res[idx++] = (byte) ((port >> 8) & 0xFF);
    res[idx] = (byte) (port & 0xFF);
    return res;
  }
}
