package com.dw.packetAnalyze.packetAnalyze.common.service;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UtilService {

  private static final Logger logger = LoggerFactory.getLogger(UtilService.class);

  public static String genTempFolder() {
    String separator = File.separator;
    String path = System.getProperty("user.home") + separator + "temp";

    String os = System.getProperty("os.name").toLowerCase();
    if (os.contains("win")) {
      path = "C:\\dongwoo\\watcher\\temp";
    }

    File dir = new File(path);
    if (!dir.exists()) {
      logger.info("make Temporary directory :: Path : {} res : {} ", path, dir.mkdirs());
    }

    return dir.getAbsolutePath();
  }

  public static String byteToIpAddress(byte[] origin) {
    if (origin == null) return "null";
    try {
      InetAddress addr = InetAddress.getByAddress(origin);
      return addr.getHostAddress();
    } catch (UnknownHostException e) {
      return Arrays.toString(origin);
    }
  }
}
