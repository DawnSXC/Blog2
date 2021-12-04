import logging

from app import init_app, db
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask import render_template, request, redirect, url_for


from app.post.models import Post
from app.user.models import User, Suggestion
from config import Config, DevelopementConfig, ProductionConfig

app = init_app("dev")

# 使用终端脚本工具启动和管理flask
manager = Manager(app)

# 启用数据迁移工具
Migrate(app, db)
# 添加数据迁移的命令到终端脚本工具中
manager.add_command('db', MigrateCommand)



@manager.command
def test():
    """Run the unit tests"""
    import unittest
    tests=unittest.TestLoader().discover('test')
    unittest.TextTestRunner(verbosity=2).run(tests)


if __name__ == '__main__':
    manager.run()
