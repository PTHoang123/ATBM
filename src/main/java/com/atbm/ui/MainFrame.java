package com.atbm.ui;

import com.atbm.ui.panels.AlgorithmPanel;
import com.atbm.ui.panels.AlgorithmPanel.PanelMode;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

public class MainFrame extends JFrame {
    public MainFrame() {
        setTitle("ATBM Crypto Tool");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1240, 820));
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        add(createHeader(), BorderLayout.NORTH);
        add(createTabs(), BorderLayout.CENTER);
    }

    private JPanel createHeader() {
        JPanel header = new JPanel(new GridBagLayout());
        header.setBackground(new Color(20, 24, 33));
        header.setBorder(BorderFactory.createEmptyBorder(22, 28, 22, 28));

        JLabel title = new JLabel("ATBM Crypto Tool");
        title.setFont(new Font("SansSerif", Font.BOLD, 30));
        title.setForeground(Color.WHITE);

        JLabel subtitle = new JLabel("mã hóa đối xứng, bất đối xứng, hash");
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 15));
        subtitle.setForeground(new Color(200, 208, 220));

        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new javax.swing.BoxLayout(text, javax.swing.BoxLayout.Y_AXIS));
        title.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        subtitle.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        text.add(title);
        text.add(javax.swing.Box.createVerticalStrut(6));
        text.add(subtitle);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        header.add(text, gbc);
        return header;
    }

    private JTabbedPane createTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        tabs.addTab("Đối xứng", new AlgorithmPanel(
                "Mã hóa đối xứng",
            "Các thuật toán demo: Dịch chuyển, Thay thế, Affine, Vigenere, Hill, Hoán vị, Blowfish và Camellia.",
            new String[]{"Dịch chuyển", "Thay thế", "Affine", "Vigenere", "Hill", "Hoán vị", "Blowfish", "Camellia"},
            PanelMode.SYMMETRIC
        ));
        tabs.addTab("Bất đối xứng", new AlgorithmPanel(
                "Mã hóa bất đối xứng",
            "Tập trung RSA với key pair có thể tự tạo theo độ dài 1024/2048 bit, nhập key sẵn và hỗ trợ file văn bản.",
                new String[]{"RSA"},
            PanelMode.ASYMMETRIC
        ));
        tabs.addTab("Hash", new AlgorithmPanel(
                "Thuật toán Hash",
                "Hỗ trợ thuật toán hash chuẩn của Java và thêm BLAKE2b-256 (qua Bouncy Castle). Băm dữ liệu nhập tay hoặc file.",
                new String[]{"MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256", "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2b-256"},
            PanelMode.HASH
        ));
        return tabs;
    }

    static {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }
    }
}
