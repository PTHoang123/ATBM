package com.atbm.ui;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.Color;
import java.awt.Font;

public class GuidePanel extends JPanel {
    public GuidePanel() {
        setLayout(new java.awt.BorderLayout());
        setBackground(Color.WHITE);

        JPanel content = new JPanel();
        content.setBackground(Color.WHITE);
        content.setBorder(BorderFactory.createEmptyBorder(22, 26, 22, 26));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        content.add(title("Hướng dẫn hoàn thiện phần chức năng"));
        content.add(Box.createVerticalStrut(14));
        content.add(bullet("• Mỗi tab tương ứng 1 nhóm thuật toán."));
        content.add(bullet("• Mã hóa đối xứng/bất đối xứng: cho chọn thuật toán, nhập hoặc tạo key, nhập plain text, xuất cipher text."));
        content.add(bullet("• Hash: nhập text, chọn thuật toán, hiển thị digest."));
        content.add(bullet("• Chữ ký số: chọn thuật toán ký, nhập private key hoặc tạo mới, ký và verify."));
        content.add(bullet("• Khi làm thật, chỉ cần thay các service placeholder bằng lớp xử lý Java Cryptography Architecture (JCA)."));
        content.add(Box.createVerticalStrut(16));
        content.add(title("Gợi ý kỹ thuật"));
        content.add(Box.createVerticalStrut(10));
        content.add(bullet("• Dùng `javax.crypto` cho AES/DES/3DES/Blowfish/ChaCha20."));
        content.add(bullet("• Dùng `java.security.KeyPairGenerator` cho RSA."));
        content.add(bullet("• Dùng `MessageDigest` cho hash."));
        content.add(bullet("• Dùng `Signature` cho chữ ký điện tử."));

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(null);
        add(scrollPane, java.awt.BorderLayout.CENTER);
    }

    private JLabel title(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("SansSerif", Font.BOLD, 22));
        label.setForeground(new Color(28, 39, 58));
        return label;
    }

    private JLabel bullet(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("SansSerif", Font.PLAIN, 15));
        label.setForeground(new Color(58, 68, 83));
        label.setBorder(BorderFactory.createEmptyBorder(6, 0, 6, 0));
        return label;
    }
}
