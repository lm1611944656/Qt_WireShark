/*
 *这个 ReadOnlyDelegate 类是一个自定义的委托类，
 *继承自 QItemDelegate，
 *用于在基于模型视图结构（如 QTableView、QTreeView 等）中实现只读行为。
 *
 *作用
 * ReadOnlyDelegate 类通过重写 createEditor 函数，禁用了编辑器的创建，使得表格或树状视图中的某些项不能被编辑。
 * 它可以用于那些不允许用户修改的模型数据项，从而实现只读效果。
 *
 *具体实现
 * createEditor 函数是 QItemDelegate 中用于创建编辑器的小部件（例如 QLineEdit、QComboBox 等），当用户在视图中双击或开始编辑某个项时会调用这个函数。
 * 在 ReadOnlyDelegate 类中，createEditor 被重写，并且返回 NULL（在新版本中使用 nullptr 更好），这意味着不会创建任何编辑器。也就是禁用了编辑操作，用户无法对该单元格进行编辑。
 *
 *使用场景
 * 这个类通常用在需要部分或全部项目处于只读状态的 QTableView 或 QTreeView 中。通过设置此类为某一列或某几列的委托，可以让这些列的数据保持只读状态。
*/

#ifndef READONLYDELEGATE_H
#define READONLYDELEGATE_H

#include <QItemDelegate>

class ReadOnlyDelegate : public QItemDelegate
{
public:
    explicit ReadOnlyDelegate(QObject *parent = nullptr);

    ~ReadOnlyDelegate();

    // 重新createEditor
    QWidget *createEditor(QWidget *parent,
                          const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;

};

#endif // READONLYDELEGATE_H
