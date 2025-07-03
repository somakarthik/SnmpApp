package com.example.myapplication;

import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.HashMap;
import java.util.Map;

public class SnmpDetailsActivity extends AppCompatActivity {
    EditText etIp, etPort, etCommunity, etUsername, etAuthPass, etPrivPass, etOid;
    Spinner spinnerVersion, spinnerAuth, spinnerPriv;
    Button btnGet;
    TextView tvResult;
    String[] versions = {"v1", "v2c", "v3"};
    String[] authProtocols = {"None", "SHA", "MD5"};
    String[] privProtocols = {"None", "DES", "AES"};
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_snmp_details);
        etIp = findViewById(R.id.etIp);
        etPort = findViewById(R.id.etPort);
        etCommunity = findViewById(R.id.etCommunity);
        etUsername = findViewById(R.id.etUsername);
        etAuthPass = findViewById(R.id.etAuthPass);
        etPrivPass = findViewById(R.id.etPrivPass);
        etOid = findViewById(R.id.etOid);
        spinnerVersion = findViewById(R.id.spinnerVersion);
        spinnerAuth = findViewById(R.id.spinnerAuth);
        spinnerPriv = findViewById(R.id.spinnerPriv);
        btnGet = findViewById(R.id.btnGet);
        tvResult = findViewById(R.id.tvResult);

        spinnerVersion.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, versions));
        spinnerAuth.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, authProtocols));
        spinnerPriv.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, privProtocols));

        btnGet.setOnClickListener(v -> doSnmpGet());
//        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
//            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
//            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
//            return insets;
//        });
    }

    private void doSnmpGet() {
        new Thread(() -> {
            String ip = etIp.getText().toString().trim();
            int port = Integer.parseInt(etPort.getText().toString().trim());
            String version = versions[spinnerVersion.getSelectedItemPosition()];
            String oidInput = etOid.getText().toString().trim();
            String result = "";

            try {
                TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
                Snmp snmp = new Snmp(transport);
                transport.listen();

                Target target;
                PDU pdu;

                if (!version.equals("v3")) {
                    CommunityTarget ct = new CommunityTarget();
                    ct.setAddress(new UdpAddress(ip + "/" + port));
                    ct.setCommunity(new OctetString(etCommunity.getText().toString()));
                    ct.setVersion(version.equals("v1") ? SnmpConstants.version1 : SnmpConstants.version2c);
                    ct.setRetries(2);
                    ct.setTimeout(1500);
                    target = ct;
                    pdu = new PDU();
                    pdu.setType(PDU.GET);
                } else {
                    USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
                    SecurityModels.getInstance().addSecurityModel(usm);

                    OID authOID = getAuthOID(spinnerAuth.getSelectedItem().toString());
                    OID privOID = getPrivOID(spinnerPriv.getSelectedItem().toString());

                    OctetString user = new OctetString(etUsername.getText().toString());
                    OctetString authPass = new OctetString(etAuthPass.getText().toString());
                    OctetString privPass = new OctetString(etPrivPass.getText().toString());

                    snmp.getUSM().addUser(user, new UsmUser(user, authOID, authPass, privOID, privPass));

                    UserTarget ut = new UserTarget();
                    ut.setAddress(new UdpAddress(ip + "/" + port));
                    ut.setSecurityName(user);
                    ut.setSecurityLevel(
                            authOID != null && privOID != null ? SecurityLevel.AUTH_PRIV :
                                    authOID != null ? SecurityLevel.AUTH_NOPRIV : SecurityLevel.NOAUTH_NOPRIV
                    );
                    ut.setVersion(SnmpConstants.version3);
                    ut.setRetries(2);
                    ut.setTimeout(1500);
                    target = ut;
                    pdu = new ScopedPDU();
                    pdu.setType(PDU.GET);
                }

                OID oid = new OID(oidInput);
                pdu.add(new VariableBinding(oid));
                ResponseEvent response = snmp.send(pdu, target);

                if (response != null && response.getResponse() != null) {
                    Variable var = response.getResponse().get(0).getVariable();
                    String raw = var.toString();
                    String syntax = var.getSyntaxString();
                    String interpreted = interpretValue(oidInput, raw);
                    result = "Raw: " + raw + "\nInterpreted: " + interpreted + "\nType: " + syntax;
                } else {
                    result = "Timeout or no response.";
                }
                snmp.close();
            } catch (Exception e) {
                result = "Error: " + e.getMessage();
            }

            String finalRes = result;
            runOnUiThread(() -> {
                tvResult.setText(finalRes);
                btnGet.setEnabled(true);
            });
        }).start();
    }

    private OID getAuthOID(String type) {
        switch (type) {
            case "SHA": return AuthSHA.ID;
            case "MD5": return AuthMD5.ID;
            default: return null;
        }
    }

    private OID getPrivOID(String type) {
        switch (type) {
            case "AES": return PrivAES128.ID;
            case "DES": return PrivDES.ID;
            default: return null;
        }
    }

    // Manual mapping example for known OIDs
    private String interpretValue(String oid, String raw) {
        Map<String, Map<String, String>> oidMaps = new HashMap<>();

        // Example OID: maps integer 1/2/3 to friendly labels
        Map<String, String> statusMap = new HashMap<>();
        statusMap.put("1", "Idle");
        statusMap.put("2", "Running");
        statusMap.put("3", "Error");
        statusMap.put("4", "Offline");

        oidMaps.put("1.3.6.1.4.1.13712.791.21.1.1.1.3.4.7.0", statusMap); // Replace with your OID

        if (oidMaps.containsKey(oid)) {
            return oidMaps.get(oid).getOrDefault(raw, "Unknown (" + raw + ")");
        }

        return raw;
    }

}