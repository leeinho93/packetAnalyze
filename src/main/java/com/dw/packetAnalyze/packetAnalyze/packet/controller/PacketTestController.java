package com.dw.packetAnalyze.packetAnalyze.packet.controller;

import static org.springframework.http.MediaType.MULTIPART_FORM_DATA_VALUE;

import com.dw.packetAnalyze.packetAnalyze.common.service.UtilService;
import com.dw.packetAnalyze.packetAnalyze.packet.dto.MissingPacketInfo;
import com.dw.packetAnalyze.packetAnalyze.packet.dto.PacketRawDataTemp;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@Tag(name = "Packet TEST Controller")
@RestController
@RequestMapping("/v2/packet/test")
public class PacketTestController {

  private final Logger logger = LoggerFactory.getLogger(this.getClass());

  @Operation(summary = "두 pcap 비교 - target 패킷 중 감시진단 인터페이스에서 검출되지 않은 패킷 목록 반환")
  @PostMapping(path = "/pcap/compare", consumes = MULTIPART_FORM_DATA_VALUE)
  public List<MissingPacketInfo> comparePcapFiles(
      @RequestPart("targetPacket") MultipartFile targetPacket,
      @RequestPart("watcherPacket") MultipartFile watcherPacket)
      throws IOException, PcapNativeException, NotOpenException {

    String tempPath = UtilService.genTempFolder();
    String sep = File.separator;

    String targetPath = tempPath + sep + "target_" + targetPacket.getOriginalFilename();
    String watcherPath = tempPath + sep + "watcher_" + watcherPacket.getOriginalFilename();

    writeTempFile(targetPacket.getBytes(), targetPath);
    writeTempFile(watcherPacket.getBytes(), watcherPath);

    Set<Long> bKeys = collectUniqueKeys(watcherPath);

    List<MissingPacketInfo> missing = new ArrayList<>();
    PcapHandle aHandle = Pcaps.openOffline(targetPath);
    try {
      Packet packet;
      while ((packet = aHandle.getNextPacket()) != null) {
        try {
          PacketRawDataTemp temp = new PacketRawDataTemp(packet, "target", aHandle.getTimestamp());
          if (!bKeys.contains(temp.getUniqueKey())) {
            missing.add(new MissingPacketInfo(temp));
          }
        } catch (Exception e) {
          logger.debug("target 패킷 파싱 실패 (스킵): {}", e.getMessage());
        }
      }
    } finally {
      aHandle.close();
    }

    logger.info("pcap 비교 완료 - 누락 패킷 수: {}", missing.size());
    return missing;
  }

  private void writeTempFile(byte[] data, String path) throws IOException {
    try (FileOutputStream os = new FileOutputStream(new File(path))) {
      os.write(data);
    }
  }

  private Set<Long> collectUniqueKeys(String path) throws PcapNativeException, NotOpenException {
    Set<Long> keys = new HashSet<>();
    PcapHandle handle = Pcaps.openOffline(path);
    try {
      Packet packet;
      while ((packet = handle.getNextPacket()) != null) {
        try {
          PacketRawDataTemp temp = new PacketRawDataTemp(packet, "b", handle.getTimestamp());
          keys.add(temp.getUniqueKey());
        } catch (Exception e) {
          logger.debug("bPcap 패킷 파싱 실패 (스킵): {}", e.getMessage());
        }
      }
    } finally {
      handle.close();
    }
    return keys;
  }
}
