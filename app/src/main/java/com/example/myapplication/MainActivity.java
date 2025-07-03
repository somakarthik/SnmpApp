package com.example.myapplication;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

import org.snmp4j.smi.OID;


public class MainActivity extends AppCompatActivity {
Button adddBtn;
    @SuppressLint("MissingInflatedId")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        adddBtn = findViewById(R.id.btnAdd);
        adddBtn.setOnClickListener(v -> new Thread(() -> {
            try {
                // Replace with your SNMP device IP
                Intent intent = new Intent(this, SnmpDetailsActivity.class);
                startActivity(intent);

            } catch (Exception e) {
                Log.e("SNMP_ERROR", "Error: " + e.getMessage(), e);
               // runOnUiThread(() -> txtResult.setText("Error: " + e.getMessage()));
            }
        }).start());

//        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
//            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
//            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
//            return insets;
//        });
    }
}