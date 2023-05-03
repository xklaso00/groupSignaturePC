package cz.vut.feec.xklaso00.groupsignature.fileManaging;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

import com.itextpdf.text.pdf.*;
import cz.vut.feec.xklaso00.groupsignature.Instructions;

import java.io.IOException;

public class PDFManager {


        public static byte[] getContentBytesOfPDF(String src){
            try {
                Path path=Paths.get(src);
                byte[] fileBytes=Files.readAllBytes(path);
                //we don't pass the file itself, since it was problematic and was holding the file even after calling the close function
                //PdfReader reader=new PdfReader(src);
                PdfReader reader=new PdfReader(fileBytes);
                int pages=reader.getNumberOfPages();
                ByteArrayOutputStream bos=new ByteArrayOutputStream();
                for (int i=0;i<pages;i++){
                    bos.write(reader.getPageContent(i+1));
                }
                byte[] contentOfPDF=bos.toByteArray();
                bos.flush();
                bos.close();
                reader.close();

                return contentOfPDF;

            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
        public static String saveSignatureToMetadata(String src, byte[] signature){
            try {
                Path path= Paths.get(src);
                byte[] fileBytes= Files.readAllBytes(path);
                PdfReader reader=new PdfReader(fileBytes);
                PdfStamper stamper=new PdfStamper(reader,new FileOutputStream(src));
                HashMap<String,String> info=reader.getInfo();
                info.put("GroupSignature", Instructions.bytesToHex(signature));
                stamper.setMoreInfo(info);
                stamper.close();
                reader.close();
                return src;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
        public static byte[] readSigFromMetadata(String src){
            byte[] sigBytes=null;

            try {
                Path path= Paths.get(src);
                byte[] fileBytes= Files.readAllBytes(path);
                PdfReader reader=new PdfReader(fileBytes);
                HashMap<String,String> info=reader.getInfo();
                String sigString=info.get("GroupSignature");
                if (sigString==null)
                    return null;
                sigBytes=Instructions.hexStringToByteArray(sigString);

            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            return sigBytes;
        }


}
