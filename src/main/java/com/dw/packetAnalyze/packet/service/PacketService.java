package com.dw.packetAnalyze.packet.service;

import com.dw.packetAnalyze.common.service.UtilService;
import com.dw.packetAnalyze.packet.dto.MissingPacketInfo;
import com.dw.packetAnalyze.packet.dto.PacketRawDataTemp;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class PacketService {

  private final Logger logger = LoggerFactory.getLogger(this.getClass());

  public List<MissingPacketInfo> comparePcapFiles(MultipartFile targetPacket, MultipartFile watcherPacket)
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

  public byte[] exportToExcel(MultipartFile targetPacket, MultipartFile watcherPacket)
      throws IOException, PcapNativeException, NotOpenException {

    List<MissingPacketInfo> missing = comparePcapFiles(targetPacket, watcherPacket);

    try (XSSFWorkbook workbook = new XSSFWorkbook();
        ByteArrayOutputStream out = new ByteArrayOutputStream()) {

      Sheet sheet = workbook.createSheet("Missing Packets");

      String[] headers = {"SeqNo", "No", "Src", "Dst", "Protocol", "Timestamp", "Length"};
      Row headerRow = sheet.createRow(0);
      for (int i = 0; i < headers.length; i++) {
        headerRow.createCell(i).setCellValue(headers[i]);
      }

      for (int i = 0; i < missing.size(); i++) {
        MissingPacketInfo info = missing.get(i);
        Row row = sheet.createRow(i + 1);
        row.createCell(0).setCellValue(info.getSeqNo());
        row.createCell(1).setCellValue(i + 1);
        row.createCell(2).setCellValue(info.getSrc());
        row.createCell(3).setCellValue(info.getDst());
        row.createCell(4).setCellValue(info.getProtocol());
        row.createCell(5).setCellValue(info.getTimestamp().toString());
        row.createCell(6).setCellValue(info.getLength());
      }

      workbook.write(out);
      return out.toByteArray();
    }
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