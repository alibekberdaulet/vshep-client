package kz.uco.shep.utils;

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.UUID;

public class XMLSignUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(kz.inessoft.proon.integration.commonutils.XMLSignUtils.class);

    static final String KEY_PASSWORD = "Aa123456";
    public static Resource loadEmployees() {
        return new ClassPathResource("key.p12");
    }

    public static XMLGregorianCalendar dateToCalendar(Date date) {
        if (date == null) return null;
        GregorianCalendar gCalendar = new GregorianCalendar();
        gCalendar.setTime(date);
        XMLGregorianCalendar xmlGregorianCalendar = null;
        try {
            xmlGregorianCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(gCalendar);
        } catch (DatatypeConfigurationException e) {
            LOGGER.error("Не удалось реализовать тип XMLGregorianCalendar", e);
        } finally {
            return xmlGregorianCalendar;
        }
    }

    public static Document parseDocument(String xml) {
        ByteArrayInputStream bais = null;
        try {
            bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = null;
            documentBuilder = dbf.newDocumentBuilder();
            return documentBuilder.parse(bais);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static Document signDocument(Document doc) {

        try {
            Provider provider = new KalkanProvider();
            Security.addProvider(provider);
            KncaXS.loadXMLSecurity();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            final String signMethod;
            final String digestMethod;
            KeyStore store = KeyStore.getInstance("PKCS12", provider.getName());
            InputStream inputStream = loadEmployees().getInputStream();

            store.load(inputStream, KEY_PASSWORD.toCharArray());
            Enumeration<String> als = store.aliases();
            String alias = null;
            while (als.hasMoreElements()) {
                alias = als.nextElement();
            }

            final PrivateKey privateKey = (PrivateKey) store.getKey(alias, KEY_PASSWORD.toCharArray());
            final X509Certificate x509Certificate = (X509Certificate) store.getCertificate(alias);
            String sigAlgOid = x509Certificate.getSigAlgOID();
            if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "sha1";
            } else if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
                digestMethod = XMLCipherParameters.SHA256;
            } else {
                signMethod = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "gost34311";
            }

            XMLSignature sig = new XMLSignature(doc, "", signMethod);

            if (doc.getFirstChild() != null) {
                doc.getFirstChild().appendChild(sig.getElement());
                Transforms transforms = new Transforms(doc);
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                transforms.addTransform(XMLCipherParameters.N14C_XML_CMMNTS);
                sig.addDocument("", transforms, digestMethod);
                sig.addKeyInfo(x509Certificate);
                sig.sign(privateKey);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return doc;
    }

    public static String signXML(String xml) {

        String result = null;

        try {
            Provider provider = new KalkanProvider();
            Security.addProvider(provider);
            KncaXS.loadXMLSecurity();
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            final Document doc = documentBuilder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            final String signMethod;
            final String digestMethod;
            KeyStore store = KeyStore.getInstance("PKCS12", provider.getName());
            InputStream inputStream = loadEmployees().getInputStream();

            store.load(inputStream, KEY_PASSWORD.toCharArray());
            Enumeration<String> als = store.aliases();
            String alias = null;
            while (als.hasMoreElements()) {
                alias = als.nextElement();
            }

            final PrivateKey privateKey = (PrivateKey) store.getKey(alias, KEY_PASSWORD.toCharArray());
            final X509Certificate x509Certificate = (X509Certificate) store.getCertificate(alias);
            String sigAlgOid = x509Certificate.getSigAlgOID();
            if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "sha1";
            } else if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
                digestMethod = XMLCipherParameters.SHA256;
            } else {
                signMethod = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "gost34311";
            }

            XMLSignature sig = new XMLSignature(doc, "", signMethod);

            if (doc.getFirstChild() != null) {
                doc.getFirstChild().appendChild(sig.getElement());
                Transforms transforms = new Transforms(doc);
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                transforms.addTransform(XMLCipherParameters.N14C_XML_CMMNTS);
                sig.addDocument("", transforms, digestMethod);
                sig.addKeyInfo(x509Certificate);
                sig.sign(privateKey);
                StringWriter os = new StringWriter();
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer trans = tf.newTransformer();
                trans.transform(new DOMSource(doc), new StreamResult(os));
                os.close();
                result = os.toString();
            }

            LOGGER.debug(result);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static void signSoap(SOAPEnvelope env) throws WSSecurityException, SOAPException, XMLSecurityException, CertificateException, PrivilegedActionException, NoSuchAlgorithmException, IOException, KeyStoreException, NoSuchProviderException, UnrecoverableKeyException {
        Provider provider = new KalkanProvider();
        Security.addProvider(provider);
        KncaXS.loadXMLSecurity();

        final String signMethod;
        final String digestMethod;
        String bodyId = "id-" + UUID.randomUUID();
        SOAPBody body = env.getBody();
        WSSecHeader secHeader = new WSSecHeader();

        secHeader.setMustUnderstand(true);
        secHeader.insertSecurityHeader(env.getOwnerDocument());

        body.addAttribute(new QName(WSConstants.WSU_NS, "Id", WSConstants.WSU_PREFIX), bodyId);
        body.setIdAttributeNS(WSConstants.WSU_NS, "Id", true);
        SOAPHeader header = env.getHeader();
        if (header == null) header = env.addHeader();
        Document doc = env.getOwnerDocument();
        Transforms transforms = new Transforms(env.getOwnerDocument());
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        KeyStore store = KeyStore.getInstance("PKCS12", provider.getName());
        InputStream inputStream = loadEmployees().getInputStream();
        /*inputStream = AccessController.doPrivileged((PrivilegedExceptionAction<FileInputStream>) () -> new FileInputStream(loadEmployees().getFile()));*/
        store.load(inputStream, KEY_PASSWORD.toCharArray());
        Enumeration<String> als = store.aliases();
        String alias = null;
        while (als.hasMoreElements()) {
            alias = als.nextElement();
        }

        final PrivateKey privateKey = (PrivateKey) store.getKey(alias, KEY_PASSWORD.toCharArray());
        final X509Certificate x509Certificate = (X509Certificate) store.getCertificate(alias);
        String sigAlgOid = x509Certificate.getSigAlgOID();
        if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
            digestMethod = Constants.MoreAlgorithmsSpecNS + "sha1";
        } else if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
            digestMethod = XMLCipherParameters.SHA256;
        } else {
            signMethod = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
            digestMethod = Constants.MoreAlgorithmsSpecNS + "gost34311";
        }

        Element c14nMethod = XMLUtils.createElementInSignatureSpace(doc, "CanonicalizationMethod");
        c14nMethod.setAttributeNS(null, "Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        Element signatureMethod = XMLUtils.createElementInSignatureSpace(doc, "SignatureMethod");
        signatureMethod.setAttributeNS(null, "Algorithm", signMethod);

        XMLSignature sig = new XMLSignature(env.getOwnerDocument(), "", signatureMethod, c14nMethod);
        sig.addDocument("#" + bodyId, transforms, digestMethod);
        sig.getSignedInfo().getSignatureMethodElement().setNodeValue(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        secHeader.getSecurityHeader().appendChild(sig.getElement());
        header.appendChild(secHeader.getSecurityHeader());
        SecurityTokenReference reference = new SecurityTokenReference(doc);
        reference.setKeyIdentifier(x509Certificate);
        sig.getKeyInfo().addUnknownElement(reference.getElement());
        sig.sign(privateKey);
    }
}


