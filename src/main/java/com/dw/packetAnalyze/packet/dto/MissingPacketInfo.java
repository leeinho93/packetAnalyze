package com.dw.packetAnalyze.packet.dto;

import java.sql.Timestamp;
import lombok.Getter;

@Getter
public class MissingPacketInfo {
  private final int no;
  private final Timestamp timestamp;

  public MissingPacketInfo(int no, Timestamp timestamp) {
    this.no = no;
    this.timestamp = timestamp;
  }
}