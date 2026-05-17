package com.atbm.ui;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;

public class OverviewPanel extends JPanel {
    public OverviewPanel() {
        setLayout(new java.awt.BorderLayout());
        setBackground(Color.WHITE);

        JPanel content = new JPanel();
        content.setBackground(Color.WHITE);
        content.setBorder(BorderFactory.createEmptyBorder(22, 26, 22, 26));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));

        content.add(createTitle("Mục tiêu đồ án"));
        content.add(Box.createVerticalStrut(12));
        content.add(createCard("1. Mã hóa đối xứng", "5-6 thuật toán, trong đó có thể dùng thư viện hỗ trợ cho 1-2 thuật toán."));
        content.add(Box.createVerticalStrut(12));
        content.add(createCard("2. Mã hóa bất đối xứng", "Triển khai RSA, cho phép tự tạo key pair theo độ dài mong muốn, nhập key sẵn và xử lý file văn bản."));
        content.add(Box.createVerticalStrut(12));
        content.add(createCard("3. Hash", "Tạo giao diện riêng cho các thuật toán băm, hỗ trợ băm dữ liệu nhập tay và băm trực tiếp file."));
        content.add(Box.createVerticalStrut(12));
        content.add(createCard("4. Chữ ký điện tử", "Thiết kế màn hình ký và xác minh chữ ký số."));
        content.add(Box.createVerticalStrut(18));
        content.add(createNote());

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(null);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, java.awt.BorderLayout.CENTER);
    }

    private Component createTitle(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("SansSerif", Font.BOLD, 24));
        label.setForeground(new Color(28, 39, 58));
        return label;
    }

    private JPanel createCard(String title, String description) {
        JPanel card = new JPanel();
        card.setBackground(new Color(247, 249, 252));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(223, 229, 238)),
                BorderFactory.createEmptyBorder(16, 18, 16, 18)
        ));
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 110));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 18));
        titleLabel.setForeground(new Color(33, 44, 67));

        JLabel descLabel = new JLabel("<html><body style='width: 820px;'>" + description + "</body></html>");
        descLabel.setFont(new Font("SansSerif", Font.PLAIN, 14));
        descLabel.setForeground(new Color(68, 79, 99));

        card.add(titleLabel);
        card.add(Box.createVerticalStrut(8));
        card.add(descLabel);
        return card;
    }

    private JPanel createNote() {
        JPanel note = createCard("Gợi ý thiết kế chức năng", "Tách lớp UI và lớp xử lý thuật toán. Giao diện chỉ lấy input, chọn thuật toán, tạo key, bấm mã hóa/giải mã/ký/xác minh, còn logic xử lý nằm trong service riêng.");
        note.setAlignmentX(Component.LEFT_ALIGNMENT);
        return note;
    }
}
