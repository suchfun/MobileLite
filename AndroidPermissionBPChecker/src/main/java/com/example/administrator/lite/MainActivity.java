package com.example.administrator.lite;

import android.content.res.AssetFileDescriptor;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import org.tensorflow.lite.Interpreter;

import java.io.FileInputStream;
import java.io.IOException;

import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

public class MainActivity extends AppCompatActivity {


    private static final String MODEL_PATH = "permission_model.tflite";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        float[][] a = new float[1][9];
        a[0][0] = 1.0f;
        a[0][1] = 1.0f;
        a[0][2] = 1.0f;

        a[0][3] = 1.0f;
        a[0][4] = 1.0f;
        a[0][5] = 0.0f;

        a[0][6] = 1.0f;
        a[0][7] = 1.0f;
        a[0][8] = 1.0f;
        float[][] output = new float[1][1];
        try (Interpreter tflite = new Interpreter(loadModelFile())) {
            tflite.run(a, output);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("==================输出==============="+output[0][0]);

    }

    private MappedByteBuffer loadModelFile() throws IOException {
        AssetFileDescriptor fileDescriptor = this.getAssets().openFd(MODEL_PATH);
        FileInputStream inputStream = new FileInputStream(fileDescriptor.getFileDescriptor());
        FileChannel fileChannel = inputStream.getChannel();
        long startOffset = fileDescriptor.getStartOffset();
        long declaredLength = fileDescriptor.getDeclaredLength();
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength);
    }
}
