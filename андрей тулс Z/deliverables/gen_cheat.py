# -*- coding: utf-8 -*-
"""Шпаргалка для быстрого рассказа: 13 слайдов = 13 строк. ReportLab."""

import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, KeepTogether)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.pdfmetrics import registerFontFamily

HERE = os.path.dirname(os.path.abspath(__file__))

pdfmetrics.registerFont(TTFont('Times New Roman', r'C:\Windows\Fonts\times.ttf'))
pdfmetrics.registerFont(TTFont('TNR-Bold', r'C:\Windows\Fonts\timesbd.ttf'))
pdfmetrics.registerFont(TTFont('Calibri', r'C:\Windows\Fonts\calibri.ttf'))
pdfmetrics.registerFont(TTFont('Calibri-Bold', r'C:\Windows\Fonts\calibrib.ttf'))
registerFontFamily('Times New Roman', normal='Times New Roman', bold='TNR-Bold')
registerFontFamily('Calibri', normal='Calibri', bold='Calibri-Bold')

# Cascade palette (тот же генератор, что у промежуточных материалов)
CARD_BG      = colors.HexColor('#eae9e6')
TABLE_STRIPE = colors.HexColor('#f1f1ee')
HEADER_FILL  = colors.HexColor('#6a5f3e')
BORDER       = colors.HexColor('#c6c0ad')
ACCENT       = colors.HexColor('#502cb9')
TEXT_PRIMARY = colors.HexColor('#242321')
TEXT_MUTED   = colors.HexColor('#838179')

title_st = ParagraphStyle('T', fontName='Calibri-Bold', fontSize=20, leading=25,
                          textColor=TEXT_PRIMARY)
sub_st = ParagraphStyle('S', fontName='Calibri', fontSize=11, leading=15,
                        textColor=TEXT_MUTED)
th = ParagraphStyle('TH', fontName='Calibri-Bold', fontSize=10, leading=13,
                    textColor=colors.white)
tdn = ParagraphStyle('TDN', fontName='Calibri-Bold', fontSize=10.5, leading=13,
                     textColor=ACCENT)
td = ParagraphStyle('TD', fontName='Times New Roman', fontSize=10.5, leading=13.5,
                    textColor=TEXT_PRIMARY)
tdm = ParagraphStyle('TDM', fontName='Times New Roman', fontSize=10.5, leading=13.5,
                     textColor=TEXT_MUTED)
stat_big = ParagraphStyle('SB', fontName='Calibri-Bold', fontSize=17, leading=20,
                          textColor=ACCENT, alignment=TA_CENTER)
stat_lab = ParagraphStyle('SL', fontName='Calibri', fontSize=8.5, leading=11,
                          textColor=TEXT_MUTED, alignment=TA_CENTER)

doc = SimpleDocTemplate(
    os.path.join(HERE, 'cheat.pdf'), pagesize=A4,
    leftMargin=1.6 * cm, rightMargin=1.6 * cm, topMargin=1.5 * cm,
    bottomMargin=1.4 * cm,
    title='Шпаргалка для рассказа — Агентик-редтиминг памяти',
    author='Команда АльфаГен', creator='Z.ai',
    subject='Быстрый нарратив по 13 слайдам объединённой колоды')
avail = A4[0] - 3.2 * cm
story = []

story.append(Paragraph('<b>Шпаргалка для рассказа</b>', title_st))
story.append(Spacer(1, 2))
story.append(Paragraph('По 13 слайдам объединённой колоды · одна строка = один слайд · '
                       'полный текст в заметках докладчика', sub_st))
story.append(Spacer(1, 10))

# три главные цифры
cw = (avail - 20) / 3
row = []
for big, lab in [('57', 'находок · 10 critical'),
                 ('19', 'подтверждённых атак'),
                 ('88%', 'согласие двух вердикторов (k=0.71)')]:
    t = Table([[Paragraph(f'<b>{big}</b>', stat_big)], [Paragraph(lab, stat_lab)]],
              colWidths=[cw])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
        ('BOX', (0, 0), (-1, -1), 0.8, BORDER),
        ('TOPPADDING', (0, 0), (-1, 0), 7), ('BOTTOMPADDING', (0, 1), (-1, 1), 7)]))
    row.append(t)
outer = Table([row], colWidths=[cw + 10, cw + 10, cw], hAlign='CENTER')
outer.setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0),
                           ('RIGHTPADDING', (0, 0), (-2, -1), 10),
                           ('RIGHTPADDING', (-1, 0), (-1, -1), 0),
                           ('TOPPADDING', (0, 0), (-1, -1), 0),
                           ('BOTTOMPADDING', (0, 0), (-1, -1), 0)]))
story.append(outer)
story.append(Spacer(1, 12))

ROWS = [
    ('1', 'Титул',
     'Ломаем память агента до выката в прод. Два независимых движка, 30+ классов атак.',
     '2 движка'),
    ('2', 'Проблема',
     'Память живёт после сброса сессии и всплывает у другого клиента. Обычные сканеры пишут только «запрос-ответ» и write-path не видят.',
     '—'),
    ('3', 'Решение',
     'Полный цикл: записали яд - активировали в новой сессии - показали последствие - собрали доказательства. Два движка проверяют друг друга.',
     'write - activate'),
    ('4', 'Архитектура',
     'Атака = файл, вход = API-контракт, доказательства - из памяти, не из ответа модели. ИБ добавляет свою атаку без кода.',
     'black-box'),
    ('5', 'Находка 01 · BAC',
     'Личная просьба клиента становится «правилом для всех» в глобальном слое памяти. Приоритет №1 кейсодателя.',
     '8/8 атак'),
    ('6', 'Находка 02 · protected',
     'Protected-режим - это авторизация чтения: запись яда он не блокирует. Защищать надо write-path.',
     'открыт в обоих'),
    ('7', 'Находка 03 · цепочки',
     'Цепочки «записал - активировал» воспроизводятся стабильно, до 9 из 9 активаций.',
     'до 9/9'),
    ('8', 'Находка 04 · ширина',
     'Одна цель, 16 формулировок: все 16 записались, активировалась 1. Вывод: фильтровать смысл записи, а не стиль.',
     '16/16 и 1/16'),
    ('9', 'Доказательство',
     'По каждой атаке цепочка: атака - память ДО - память ПОСЛЕ - оценка - итог. Прогоны подписаны sha256, правку ловит verify.',
     'sha256'),
    ('10', 'Покрытие',
     '57 находок, 111 триггеров. Все три сценария кейсодателя закрыты, выгрузка SARIF для ASOC готова.',
     '3 сценария'),
    ('11', 'Границы',
     'Мы делаем надёжный детект. Не обещаем «полную защищённость» и не заменяем анализ ИБ.',
     'честно'),
    ('12', 'Ценность',
     'Контракт - батарея - finding - go/no-go. Встраивается в MLSecOps: pluggable-атаки + SARIF.',
     '4 шага'),
    ('13', 'Финал',
     'Память - поверхность атаки, protected её не закрывает. Мы даём доказательства и расширяемость.',
     '—'),
]

data = [[Paragraph('<b>#</b>', th), Paragraph('<b>Слайд</b>', th),
         Paragraph('<b>Что сказать (одной фразой)</b>', th),
         Paragraph('<b>Цифра</b>', th)]]
for n, name, say, num in ROWS:
    data.append([Paragraph(n, tdn), Paragraph(f'<b>{name}</b>', td),
                 Paragraph(say, td), Paragraph(num, tdm)])

widths = [0.05 * avail, 0.20 * avail, 0.61 * avail, 0.14 * avail]
t = Table(data, colWidths=widths, hAlign='CENTER', repeatRows=1)
style = [('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
         ('BACKGROUND', (0, 0), (-1, 0), HEADER_FILL),
         ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
         ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6),
         ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]
for i in range(1, len(ROWS) + 1):
    if i % 2 == 0:
        style.append(('BACKGROUND', (0, i), (-1, i), TABLE_STRIPE))
t.setStyle(TableStyle(style))
story.append(t)
story.append(Spacer(1, 10))

story.append(KeepTogether([
    Paragraph('<b>Если дают 1 минуту вместо пяти</b>', ParagraphStyle(
        'H', fontName='Calibri-Bold', fontSize=12, leading=16,
        textColor=TEXT_PRIMARY, spaceAfter=4)),
    Paragraph('Память агента — отдельная поверхность атаки: отравленный факт переживает '
              'сброс сессии и всплывает у других клиентов. Мы построили инструмент, который '
              'доказывает это на фактах: записал яд, активировал в новой сессии, показал '
              'последствие и собрал доказательства из памяти. 57 находок, 19 полных '
              'подтверждений; запись яда не зависит от формулировки (16/16), значит '
              'детектить надо смысл, а не стиль. Выгрузка для ASOC готова.', td)]))

doc.build(story)
print('cheat.pdf ok')
