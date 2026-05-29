package com.dw.packetAnalyze.packetAnalyze.packet.domain;

import lombok.Getter;

@Getter
public enum EProtocol {
  MMS(true, true, true, true),
  GOOSE(false, true, true, false),
  DNP(false, true, false, true),
  NTP(false, false, false, true),
  SNMP(false, false, false, true),
  SNMP_TRAP(false, false, false, true),
  SV(false, false, false, false),
  ICMP(false, false, false, true),
  NONE(false, false, false, false);

  private final boolean isConnectionManage;
  private final boolean isTrafficMeasure;
  private final boolean isTopTrafficMeasure;
  private final boolean hasIp;

  EProtocol(boolean connectionManage, boolean isTrafficMeasure, boolean isTopTrafficMeasure, boolean hasIp) {
    this.isConnectionManage = connectionManage;
    this.isTrafficMeasure = isTrafficMeasure;
    this.isTopTrafficMeasure = isTopTrafficMeasure;
    this.hasIp = hasIp;
  }
}
