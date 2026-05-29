package com.dw.packetAnalyze.packetAnalyze.packet.dto;

import com.dw.packetAnalyze.packetAnalyze.common.service.HashKeyUtil;
import com.dw.packetAnalyze.packetAnalyze.common.service.UtilService;
import com.dw.packetAnalyze.packetAnalyze.packet.domain.EProtocol;
import java.sql.Timestamp;
import java.util.Locale;
import java.util.Map;
import lombok.Getter;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;

public class PacketRawDataTemp {

  private static final Map<Integer, EProtocol> PORT_PROTOCOL_MAP = Map.of(
      102, EProtocol.MMS,
      20000, EProtocol.DNP,
      20200, EProtocol.DNP,
      123, EProtocol.NTP,
      161, EProtocol.SNMP,
      162, EProtocol.SNMP_TRAP
  );

  private final Packet packet;
  @Getter private final Timestamp timestamp;
  @Getter private final byte[] srcMac;
  @Getter private final byte[] dstMac;
  @Getter private final int vlan;
  @Getter private final byte[] srcIp;
  @Getter private final byte[] dstIp;
  @Getter private final int srcPort;
  @Getter private final int dstPort;
  @Getter private byte[] payload;
  @Getter private EProtocol protocol;
  @Getter private long uniqueKey;
  @Getter private long seqNo;
  @Getter private long ackNo;
  @Getter private Boolean fin;
  @Getter private Boolean rst;
  @Getter private Boolean ack;
  @Getter private Boolean syn;
  @Getter private Boolean psh;
  @Getter private Integer identification;

  public PacketRawDataTemp(Packet packet, String ifName, Timestamp timestamp) {
    this.packet = packet;
    this.timestamp = timestamp;
    EthernetPacket eth = packet.get(EthernetPacket.class);
    EthernetPacket.EthernetHeader ethHeader = eth.getHeader();
    EtherType type = ethHeader.getType();
    Packet payload = eth.getPayload();
    int vlan = 1;
    if (type.equals(EtherType.DOT1Q_VLAN_TAGGED_FRAMES)) {
      Dot1qVlanTagPacket vlanTagPacket = packet.get(Dot1qVlanTagPacket.class);
      Dot1qVlanTagPacket.Dot1qVlanTagHeader vlanTagHeader = vlanTagPacket.getHeader();
      vlan = vlanTagHeader.getVidAsInt();
      type = vlanTagHeader.getType();
      payload = vlanTagPacket.getPayload();
    }

    this.vlan = vlan;
    int etherType = type.value() & 0xFFFF;

    this.srcMac = ethHeader.getSrcAddr().getAddress();
    this.dstMac = ethHeader.getDstAddr().getAddress();

    int identification = payload.length();

    switch (etherType) {
      case 0x0800:
        IpV4Packet.IpV4Header ipV4Header = payload.get(IpV4Packet.class).getHeader();
        this.srcIp = ipV4Header.getSrcAddr().getAddress();
        this.dstIp = ipV4Header.getDstAddr().getAddress();
        identification = ipV4Header.getIdentificationAsInt();
        break;
      case 0x86DD:
        IpV6Packet.IpV6Header ipV6Header = payload.get(IpV6Packet.class).getHeader();
        this.srcIp = ipV6Header.getSrcAddr().getAddress();
        this.dstIp = ipV6Header.getDstAddr().getAddress();
        identification = ipV6Header.getFlowLabel().value();
        break;
      default:
        this.srcIp = null;
        this.dstIp = null;
        this.srcPort = -1;
        this.dstPort = -1;
        this.uniqueKey = HashKeyUtil.ehterUniqueKey(dstMac, vlan, payload.getRawData());
        this.payload = payload.getRawData();
        if (etherType == 0x88BA) {
          this.protocol = EProtocol.SV;
        } else if (etherType == 0x88B8) {
          this.protocol = EProtocol.GOOSE;
        } else {
          this.protocol = EProtocol.NONE;
        }
        return;
    }

    if (payload.contains(TcpPacket.class)) {
      TcpPacket tcpPacket = payload.get(TcpPacket.class);
      TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
      this.srcPort = tcpHeader.getSrcPort().valueAsInt();
      this.dstPort = tcpHeader.getDstPort().valueAsInt();
      this.seqNo = tcpHeader.getSequenceNumberAsLong();
      this.ackNo = tcpHeader.getAcknowledgmentNumberAsLong();
      this.fin = tcpHeader.getFin();
      this.rst = tcpHeader.getRst();
      this.ack = tcpHeader.getAck();
      this.syn = tcpHeader.getSyn();
      this.psh = tcpHeader.getPsh();
      this.payload = tcpPacket.getPayload() != null ? tcpPacket.getPayload().getRawData() : null;
    } else if (payload.contains(UdpPacket.class)) {
      UdpPacket udpPacket = payload.get(UdpPacket.class);
      UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
      this.srcPort = udpHeader.getSrcPort().valueAsInt();
      this.dstPort = udpHeader.getDstPort().valueAsInt();
      this.payload = udpPacket.getPayload() != null ? udpPacket.getPayload().getRawData() : null;
    } else {
      this.srcPort = -1;
      this.dstPort = -1;
    }

    if (payload.contains(IcmpV4CommonPacket.class) || payload.contains(IcmpV6CommonPacket.class)) {
      this.protocol = EProtocol.ICMP;
    } else {
      setProtocolByPort();
    }

    setUniqueKey(identification);
  }

  private void setProtocolByPort() {
    if (this.srcPort == -1 || this.dstPort == -1) {
      this.protocol = EProtocol.NONE;
      return;
    }
    EProtocol temp = PORT_PROTOCOL_MAP.getOrDefault(this.srcPort, EProtocol.NONE);
    if (temp.equals(EProtocol.NONE)) {
      temp = PORT_PROTOCOL_MAP.getOrDefault(this.dstPort, EProtocol.NONE);
    }
    this.protocol = temp;
  }

  private void setUniqueKey(int identification) {
    this.identification = identification;
    this.uniqueKey = HashKeyUtil.ipKey(this.srcIp, this.dstIp, this.srcPort, this.dstPort, identification);
  }

  public String getSrcString() {
    if (this.srcIp == null) {
      return ByteArrays.toHexString(this.srcMac, ":").toUpperCase(Locale.ROOT);
    }
    return UtilService.byteToIpAddress(srcIp);
  }

  public String getDstString() {
    if (this.dstIp == null) {
      return ByteArrays.toHexString(this.dstMac, ":").toUpperCase(Locale.ROOT);
    }
    return UtilService.byteToIpAddress(this.dstIp);
  }

  public int getTotalLength() {
    return packet.length();
  }

  public long getSessionDirectionKey() {
    return HashKeyUtil.ipSessionDirectionKey(srcIp, dstIp, srcPort, dstPort);
  }

  public boolean isAckOnly() {
    if (ack == null) {
      return false;
    }
    return ack && !fin && !psh && !syn;
  }
}
