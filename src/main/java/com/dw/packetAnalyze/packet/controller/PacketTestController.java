package com.dw.packetAnalyze.packet.controller;

import static org.springframework.http.MediaType.MULTIPART_FORM_DATA_VALUE;

import com.dw.packetAnalyze.packet.dto.MissingPacketInfo;
import com.dw.packetAnalyze.packet.service.PacketService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@Tag(name = "Packet TEST Controller")
@RestController
@RequestMapping("/v2/packet/test")
@RequiredArgsConstructor
public class PacketTestController {

  private final PacketService packetService;

  @Operation(summary = "두 pcap 비교 - target 패킷 중 감시진단 인터페이스에서 검출되지 않은 패킷 목록 반환")
  @PostMapping(path = "/pcap/compare", consumes = MULTIPART_FORM_DATA_VALUE)
  public List<MissingPacketInfo> comparePcapFiles(
      @RequestPart("targetPacket") MultipartFile targetPacket,
      @RequestPart("watcherPacket") MultipartFile watcherPacket)
      throws IOException, PcapNativeException, NotOpenException {

    return packetService.comparePcapFiles(targetPacket, watcherPacket);
  }

  @Operation(summary = "두 pcap 비교 결과 엑셀 다운로드 - 누락 패킷 목록을 xlsx 파일로 반환")
  @PostMapping(path = "/pcap/compare/excel", consumes = MULTIPART_FORM_DATA_VALUE)
  public ResponseEntity<byte[]> comparePcapFilesExcel(
      @RequestPart("targetPacket") MultipartFile targetPacket,
      @RequestPart("watcherPacket") MultipartFile watcherPacket)
      throws IOException, PcapNativeException, NotOpenException {

    byte[] excelBytes = packetService.exportToExcel(targetPacket, watcherPacket);

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"));
    headers.setContentDisposition(ContentDisposition.attachment().filename("missing_packets.xlsx").build());

    return ResponseEntity.ok().headers(headers).body(excelBytes);
  }
}