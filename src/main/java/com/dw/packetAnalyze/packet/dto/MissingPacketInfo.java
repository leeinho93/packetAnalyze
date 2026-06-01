package com.dw.packetAnalyze.packet.dto;

import java.sql.Timestamp;
import lombok.Getter;

@Getter
public class MissingPacketInfo {
  private final String src;
  private final String dst;
  private final String protocol;
  private final Timestamp timestamp;
  private final int length;
  private final long uniqueKey;
  private final long seqNo;

  public MissingPacketInfo(PacketRawDataTemp temp) {
    this.src = temp.getSrcString();
    this.dst = temp.getDstString();
    this.protocol = temp.getProtocol().name();
    this.timestamp = temp.getTimestamp();
    this.length = temp.getTotalLength();
    this.uniqueKey = temp.getUniqueKey();
    this.seqNo = temp.getSeqNo();
  }
}
