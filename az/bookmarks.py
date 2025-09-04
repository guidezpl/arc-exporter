from pathlib import Path
from .paths import ARC_SIDEBAR
from .utils import ensure, read_json

def export_pinned_bookmarks(out_html: Path, space_title: str | None = None):
    ensure(out_html.parent)
    data = read_json(ARC_SIDEBAR)
    
    # Create a mapping from profile display names to space names
    # This is needed because Arc profile names don't match sidebar space names
    profile_to_space_mapping = {
        "Main": "Home",        # Main profile maps to Home space
        "Business": "Awaiten", # Business profile maps to Awaiten space  
        "School": "School",    # School profile maps to School space
        "sync.": "sync.",      # sync. profile maps to sync. space
    }
    
    # Use the mapping to get the correct space name
    mapped_space_title = profile_to_space_mapping.get(space_title, space_title)
    
    html = _convert_json_to_html_legacy(data, mapped_space_title)
    with out_html.open("w", encoding="utf-8") as f:
        f.write(html)

def _convert_json_to_html_legacy(json_data: dict, space_title: str | None = None) -> str:
    containers = json_data["sidebar"]["containers"]
    try:
        target = next(i + 1 for i, c in enumerate(containers) if "global" in c)
    except StopIteration:
        raise ValueError("No container with 'global' found in the sidebar data")

    spaces = _get_spaces_legacy(json_data["sidebar"]["containers"][target]["spaces"])
    items = json_data["sidebar"]["containers"][target]["items"]

    bookmarks = _convert_to_bookmarks_legacy(spaces, items, space_title)
    return _convert_bookmarks_to_html_legacy(bookmarks)

def _get_spaces_legacy(spaces: list) -> dict:
    spaces_names = {"pinned": {}, "unpinned": {}}
    n = 1
    for space in spaces:
        title = space["title"] if isinstance(space, dict) and "title" in space else f"Space {n}"; n += 1
        if isinstance(space, dict):
            containers = space.get("newContainerIDs", [])
            for i in range(len(containers)):
                if isinstance(containers[i], dict):
                    if "pinned" in containers[i] and i + 1 < len(containers):
                        spaces_names["pinned"][str(containers[i + 1])] = title
                    elif "unpinned" in containers[i] and i + 1 < len(containers):
                        spaces_names["unpinned"][str(containers[i + 1])] = title
    return spaces_names

def _convert_to_bookmarks_legacy(spaces: dict, items: list, space_title: str | None) -> dict:
    bookmarks = {"bookmarks": []}
    item_dict = {item["id"]: item for item in items if isinstance(item, dict)}

    def recurse_into_children(parent_id: str) -> list:
        children = []
        for item_id, item in item_dict.items():
            if item.get("parentID") == parent_id:
                if "data" in item and "tab" in item["data"]:
                    children.append({
                        "title": item.get("title") or item["data"]["tab"].get("savedTitle", ""),
                        "type": "bookmark",
                        "url": item["data"]["tab"].get("savedURL", ""),
                    })
                elif "title" in item:
                    child_folder = {
                        "title": item["title"],
                        "type": "folder",
                        "children": recurse_into_children(item_id),
                    }
                    children.append(child_folder)
        return children

    for space_id, space_name in spaces["pinned"].items():
        if space_title is not None and space_name != space_title:
            continue
        space_folder = {
            "title": space_name,
            "type": "folder",
            "children": recurse_into_children(space_id),
        }
        bookmarks["bookmarks"].append(space_folder)
    # No fallback - if filter produced nothing, return empty bookmarks
    # This ensures profile isolation and prevents combining bookmarks from all profiles
    return bookmarks

def _convert_bookmarks_to_html_legacy(bookmarks: dict) -> str:
    html_str = """<!DOCTYPE NETSCAPE-Bookmark-file-1>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>"""
    def traverse_dict(d: list, html_str: str, level: int) -> str:
        indent = "\t" * level
        for item in d:
            if item["type"] == "folder":
                html_str += f'\n{indent}<DT><H3>{item["title"]}</H3>'
                html_str += f"\n{indent}<DL><p>"
                html_str = traverse_dict(item["children"], html_str, level + 1)
                html_str += f"\n{indent}</DL><p>"
            elif item["type"] == "bookmark":
                html_str += f'\n{indent}<DT><A HREF="{item["url"]}">{item["title"]}</A>'
        return html_str
    html_str = traverse_dict(bookmarks["bookmarks"], html_str, 1)
    html_str += "\n</DL><p>"
    return html_str

